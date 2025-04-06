from flask import Flask, request, Response
import os
import hmac
import hashlib
import requests
import time
from anthropic import Anthropic
import jwt
from base64 import b64decode
import json
import re

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

def get_pr_files(repo_full_name, pr_number, token):
    """Get detailed PR files info including patch data"""
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json"
    }
    
    response = requests.get(
        f"https://api.github.com/repos/{repo_full_name}/pulls/{pr_number}/files",
        headers=headers
    )
    
    if response.status_code != 200:
        print(f"Error getting PR files: {response.status_code}")
        return []
        
    return response.json()


def post_pr_review(repo_full_name, pr_number, review_body, token, comments=None):
    """Post a review to the PR with optional line comments"""
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json"
    }
    
    payload = {
        "body": review_body,
        "event": "COMMENT"  # Can be APPROVE, REQUEST_CHANGES, or COMMENT
    }

    # Add line-specific comments if provided
    if comments and len(comments) > 0:
        payload["comments"] = comments 

    response = requests.post(
        f"https://api.github.com/repos/{repo_full_name}/pulls/{pr_number}/reviews",
        headers=headers,
        json=payload
    )
    
    return response.status_code

def extract_line_number_from_patch(patch, line_content):
    """Extract the new file line number from patch data"""
    if not patch:
        return None
    
    lines = patch.split('\n')
    current_line_number = None
    
    for line in lines:
        if line.startswith('@@'):
            # Parse the @@ -a,b +c,d @@ line to get starting line numbers
            match = re.search(r'\+(\d+)', line)
            if match:
                current_line_number = int(match.group(1))
            continue
        
        if current_line_number is not None:
            if line.startswith('+') and line[1:].strip() == line_content.strip():
                return current_line_number
            if not line.startswith('-'):
                current_line_number += 1
    
    return None

def generate_review_summary(diff, pr_title, pr_description):
    """Generate a summary using Claude"""
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

Please provide a high-level summary review that includes:
1. A brief summary of what the PR changes (1-2 sentences)
2. Your general opinion on the changes
3. Key strengths of the PR
4. 1-3 main areas of improvement, if any

Keep this summary concise (about 3-5 paragraphs max). Format your response in Markdown.

Do not make specific line-by-line comments in this summary as those will be handled separately."""

    try:
        response = anthropic_client.messages.create(
            model="claude-3-5-sonnet-20241022",  # Use your preferred Claude model
            max_tokens=4000,
            system="You are an expert code reviewer. Be helpful, specific, and constructive.",
            messages=[
                {"role": "user", "content": [{"type": "text", "text": prompt}]}
            ]
        )
        return response.content[0].text
    except Exception as e:
        print(f"Error generating review summary: {e}")
        return f"I encountered an error while reviewing this PR. Error details: {str(e)}"

def analyze_file_for_comments(file_data):
    """Analyze a single file and generate specific line comments"""
    filename = file_data.get("filename")
    patch = file_data.get("patch", "")
    
    if not patch:
        return []
    
    # Preparing file context
    prompt = f"""You are a helpful code reviewer. You're reviewing changes to a file in a pull request.

Filename: {filename}
File changes:
```
{patch}
```

Your task is to identify specific lines of code that could benefit from comments. For each issue you find, provide:
1. The exact line of code (just the code itself, unchanged)
2. Your comment about that line, including suggestions for improvement if applicable

Only comment on the most important issues (maximum 3-5 comments per file). Focus on:
- Potential bugs or errors
- Security issues
- Performance concerns
- Code readability or maintainability
- Best practices violations

Format your response as JSON like this:
[
  {{
    "line": "the exact code line",
    "comment": "your detailed comment and suggestion"
  }},
  ...
]

If there are no issues worth commenting on, return an empty array: []"""

    try:
        response = anthropic_client.messages.create(
            model="claude-3-5-sonnet-20241022",  # Use your preferred Claude model
            max_tokens=4000,
            system="You are an expert code reviewer focusing on specific code details.",
            messages=[
                {"role": "user", "content": [{"type": "text", "text": prompt}]}
            ]
        )
        
        # Parse the JSON response
        content = response.content[0].text
        print(content)
        
        # Extract JSON data - find content between square brackets
        json_match = re.search(r'\[\s*\{.*\}\s*\]', content, re.DOTALL)
        if json_match:
            try:
                return json.loads(json_match.group(0))
            except json.JSONDecodeError:
                print(f"Failed to parse JSON from: {content}")
        
        # If no valid JSON found or empty array returned
        if "[]" in content:
            return []
            
        # Attempt to parse the whole response if needed
        try:
            return json.loads(content)
        except json.JSONDecodeError:
            print(f"Could not parse any JSON from Claude's response: {content}")
            return []
            
    except Exception as e:
        print(f"Error analyzing file {filename}: {e}")
        return []

def format_line_comments_for_github(repo_full_name, pr_number, token, file_comments):
    """Convert our internal comment format to GitHub's expected format"""
    github_comments = []
    
    # Get PR files to map line numbers
    pr_files = get_pr_files(repo_full_name, pr_number, token)
    file_patches = {file["filename"]: file.get("patch", "") for file in pr_files}
    
    for filename, comments in file_comments.items():
        patch = file_patches.get(filename, "")
        
        for comment_data in comments:
            line_content = comment_data.get("line", "").strip()
            comment_body = comment_data.get("comment", "")
            
            # Find the line number in the patch
            line_number = extract_line_number_from_patch(patch, line_content)
            
            if line_number:
                github_comments.append({
                    "path": filename,
                    "line": line_number, 
                    "body": comment_body
                })
    
    return github_comments

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
                    
                # Get PR diff for summary
                diff = get_pr_diff(repo_full_name, pr_number, token)
                if not diff:
                    return Response("Failed to get PR diff", status=500)
                    
                # Get PR files for line comments
                pr_files = get_pr_files(repo_full_name, pr_number, token)

                # Generate overall summary review
                summary = generate_review_summary(diff, pr_title, pr_description)

                # Process each file for specific comments

                file_comments = {}

                for file_data in pr_files:
                    filename = file_data.get("filename")
                    comments = analyze_file_for_comments(file_data)
                    if comments:
                        file_comments[filename] = comments

                # Format comments for GitHub API
                github_comments = format_line_comments_for_github(repo_full_name, pr_number, token, file_comments)

                # Post review with comments
                status_code = post_pr_review(repo_full_name, pr_number, summary, token, github_comments)
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
