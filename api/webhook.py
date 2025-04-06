# api/webhook.py - Updated with custom Anthropic domain support
from flask import Flask, request, Response
import os
import hmac
import hashlib
import requests
import time
from anthropic import Anthropic
import jwt
from base64 import b64decode

# Anthropic configuration with custom domain support
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY")
ANTHROPIC_API_URL = os.environ.get("ANTHROPIC_API_URL")

# Initialize Anthropic client with custom domain if specified
anthropic_client = Anthropic(
    api_key=ANTHROPIC_API_KEY,
    base_url=ANTHROPIC_API_URL
)

# GitHub App configuration
APP_ID = os.environ.get("GITHUB_APP_ID")
PRIVATE_KEY = os.environ.get("GITHUB_PRIVATE_KEY", "")  # Store as Base64 in Vercel
WEBHOOK_SECRET = os.environ.get("GITHUB_WEBHOOK_SECRET", "")

# If PRIVATE_KEY is base64 encoded, decode it
if PRIVATE_KEY and PRIVATE_KEY.startswith("LS0t"):
    PRIVATE_KEY = b64decode(PRIVATE_KEY).decode('utf-8')

app = Flask(__name__)

def verify_webhook(request_data, signature_header):
    """Verify the webhook signature"""
    if not WEBHOOK_SECRET:
        return True  # Skip verification if no secret (not recommended for production)
    
    signature = "sha256=" + hmac.new(
        WEBHOOK_SECRET.encode('utf-8'),
        request_data,
        hashlib.sha256
    ).hexdigest()
    
    return hmac.compare_digest(signature, signature_header)

def get_jwt():
    """Generate a JWT for GitHub App authentication"""
    if not PRIVATE_KEY or not APP_ID:
        raise ValueError("Missing GitHub App credentials")
    
    now = int(time.time())
    payload = {
        'iat': now,
        'exp': now + (10 * 60),  # 10 minute expiration
        'iss': APP_ID
    }
    
    token = jwt.encode(payload, PRIVATE_KEY, algorithm='RS256')
    return token

def get_installation_token(installation_id):
    """Get an installation access token"""
    token = get_jwt()
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github.v3+json"
    }
    
    response = requests.post(
        f"https://api.github.com/app/installations/{installation_id}/access_tokens",
        headers=headers
    )
    
    if response.status_code != 201:
        print(f"Error getting installation token: {response.status_code}")
        print(response.text)
        return None
        
    return response.json()["token"]

def get_pr_diff(repo_full_name, pr_number, token):
    """Get the PR diff"""
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3.diff"
    }
    
    response = requests.get(
        f"https://api.github.com/repos/{repo_full_name}/pulls/{pr_number}",
        headers=headers
    )
    
    if response.status_code != 200:
        print(f"Error getting PR diff: {response.status_code}")
        return None
        
    return response.text

def post_pr_review(repo_full_name, pr_number, review_body, token):
    """Post a review to the PR"""
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json"
    }
    
    payload = {
        "body": review_body,
        "event": "COMMENT"  # Can be APPROVE, REQUEST_CHANGES, or COMMENT
    }
    
    response = requests.post(
        f"https://api.github.com/repos/{repo_full_name}/pulls/{pr_number}/reviews",
        headers=headers,
        json=payload
    )
    
    return response.status_code

def generate_review(diff, pr_title, pr_description):
    """Generate a review using Claude"""
    # Truncate diff if too large to avoid token limits
    max_diff_length = 100000
    truncated = False
    
    if len(diff) > max_diff_length:
        diff = diff[:max_diff_length]
        truncated = True

    prompt = f"""You are a helpful code reviewer. You're reviewing a pull request with the following:

Title: {pr_title}
Description: {pr_description}

Here's the diff:
```
{diff}
```
{"(Diff was truncated due to size)" if truncated else ""}

Please provide a thorough review that includes:
1. A brief summary of what the PR changes
2. Potential issues or bugs
3. Suggestions for improvement
4. Any security concerns
5. Code style recommendations

Format your response in Markdown."""

    try:
        response = anthropic_client.messages.create(
            model="claude-3-5-haiku-20240307",  # Use your preferred Claude model
            max_tokens=4000,
            system="You are an expert code reviewer. Be helpful, specific, and constructive.",
            messages=[
                {"role": "user", "content": prompt}
            ]
        )
        
        return response.content[0].text
    except Exception as e:
        print(f"Error generating review: {e}")
        return f"I encountered an error while reviewing this PR. Error details: {str(e)}"

@app.route('/', methods=['GET'])
def hello():
    return Response("hello", status=200)

@app.route('/api/webhook', methods=['POST'])
def webhook_handler():
    """Handle GitHub webhooks - this is the main Vercel function"""
    # Verify signature
    signature = request.headers.get('X-Hub-Signature-256')
    if not verify_webhook(request.data, signature):
        return Response("Unauthorized", status=401)
    
    # Parse the webhook payload
    event = request.headers.get('X-GitHub-Event')
    payload = request.json
    
    # Only process pull request events
    if event == 'pull_request':
        action = payload.get('action')
        
        # Process only when PR is opened or synchronized (new commits pushed)
        if action in ['opened', 'synchronize']:
            pr = payload.get('pull_request', {})
            repo = payload.get('repository', {})
            installation_id = payload.get('installation', {}).get('id')
            
            if not (pr and repo and installation_id):
                return Response("Missing required data", status=400)
                
            pr_number = pr.get('number')
            repo_full_name = repo.get('full_name')
            pr_title = pr.get('title', '')
            pr_description = pr.get('body', '') or 'No description provided.'
            
            try:
                # Get installation token
                token = get_installation_token(installation_id)
                if not token:
                    return Response("Failed to get installation token", status=500)
                    
                # Get PR diff
                diff = get_pr_diff(repo_full_name, pr_number, token)
                if not diff:
                    return Response("Failed to get PR diff", status=500)
                    
                # Generate review
                review = generate_review(diff, pr_title, pr_description)
                
                # Post review
                status_code = post_pr_review(repo_full_name, pr_number, review, token)
                if status_code >= 200 and status_code < 300:
                    return Response("Review posted successfully", status=200)
                else:
                    return Response(f"Failed to post review: {status_code}", status=500)
            except Exception as e:
                print(f"Error processing webhook: {e}")
                return Response(f"Error: {str(e)}", status=500)
    
    return Response("Event processed", status=200)

# For local development
if __name__ == '__main__':
    app.run(debug=True)
