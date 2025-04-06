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
import threading

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
    """Analyze a single file and generate specific line comments with GitHub change suggestions"""
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
2. Your comment about that line, including suggestions for improvement
3. A suggested code replacement when applicable

Only comment on the most important issues (maximum 3-5 comments per file). Focus on:
- Potential bugs or errors
- Security issues
- Performance concerns
- Code readability or maintainability
- Best practices violations

When suggesting code changes, ensure they're complete replacements for the line mentioned, and make sure they're valid syntax.

Format your response as JSON like this:
[
  {{
    "line": "the exact code line",
    "comment": "your detailed comment explaining the issue",
    "suggestion": "the improved code that should replace the original line"
  }},
  ...
]

If you don't have a specific code suggestion, omit the 'suggestion' field.
If there are no issues worth commenting on, return an empty array: []"""

    try:
        response = anthropic_client.messages.create(
            model="claude-3-5-sonnet-20241022",  # Use your preferred Claude model
            max_tokens=4000,
            system="You are an expert code reviewer focusing on specific code details. When suggesting improvements, provide concrete code examples.",
            messages=[
                {"role": "user", "content": [{"type": "text", "text": prompt}]}
            ]
        )
        
        # Parse the JSON response
        content = response.content[0].text
        
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
    """Convert our internal comment format to GitHub's expected format with change suggestions"""
    github_comments = []
    
    # Get PR files to map line numbers
    pr_files = get_pr_files(repo_full_name, pr_number, token)
    file_patches = {file["filename"]: file.get("patch", "") for file in pr_files}
    
    for filename, comments in file_comments.items():
        patch = file_patches.get(filename, "")
        
        for comment_data in comments:
            line_content = comment_data.get("line", "").strip()
            comment_body = comment_data.get("comment", "")
            suggestion = comment_data.get("suggestion", "")
            
            # Find the line number in the patch
            line_number = extract_line_number_from_patch(patch, line_content)
            
            if line_number:
                # Format comment with GitHub suggestion syntax if a suggestion is provided
                formatted_comment = comment_body
                if suggestion:
                    formatted_comment += f"\n\n```suggestion\n{suggestion}\n```"
                
                github_comments.append({
                    "path": filename,
                    "line": line_number, 
                    "body": formatted_comment
                })
    
    return github_comments

review_tasks = {}

def process_pr_review_async(payload):
    """Process PR review asynchronously in a separate thread"""
    try:
        pr = payload.get('pull_request', {})
        repo = payload.get('repository', {})
        installation_id = payload.get('installation', {}).get('id')
        
        pr_number = pr.get('number')
        repo_full_name = repo.get('full_name')
        pr_title = pr.get('title', '')
        pr_description = pr.get('body', '') or 'No description provided.'
        
        # Get installation token
        token = get_installation_token(installation_id)
        if not token:
            print(f"Failed to get installation token for PR #{pr_number}")
            return
            
        # First, post an initial comment that review is in progress
        post_initial_comment(repo_full_name, pr_number, token)
        
        # Get PR diff for summary
        diff = get_pr_diff(repo_full_name, pr_number, token)
        if not diff:
            print(f"Failed to get PR diff for PR #{pr_number}")
            return
            
        # Truncate diff if too large
        max_diff_length = 50000
        if len(diff) > max_diff_length:
            diff = diff[:max_diff_length] + "\n\n[Diff truncated due to size]"
            
        # Generate overall summary review
        summary = generate_review_summary(diff, pr_title, pr_description)

        # Get PR files for line comments
        pr_files = get_pr_files(repo_full_name, pr_number, token)
        
        # Limit number of files to analyze
        MAX_FILES_TO_ANALYZE = 3
        files_to_analyze = filter_files_to_analyze(pr_files, MAX_FILES_TO_ANALYZE)

        # Process each file for specific comments
        file_comments = {}
        for file_data in files_to_analyze:
            try:
                filename = file_data.get("filename")
                comments = analyze_file_for_comments(file_data)
                if comments:
                    file_comments[filename] = comments
            except Exception as e:
                print(f"Error analyzing file {file_data.get('filename')}: {e}")
                continue

        # Format comments for GitHub API
        github_comments = format_line_comments_for_github(repo_full_name, pr_number, token, file_comments)

        # Add note about limited file analysis if needed
        if len(pr_files) > MAX_FILES_TO_ANALYZE:
            summary += f"\n\n---\n\n*Note: Due to performance constraints, I've only analyzed {MAX_FILES_TO_ANALYZE} files out of {len(pr_files)} total files in this PR.*"

        # Post review with comments
        status_code = post_pr_review(repo_full_name, pr_number, summary, token, github_comments)
        if status_code < 200 or status_code >= 300:
            print(f"Failed to post review for PR #{pr_number}: {status_code}")
            
    except Exception as e:
        print(f"Error in async PR review process: {e}")
    finally:
        # Remove task from tracking dictionary
        task_key = f"{repo_full_name}_{pr_number}"
        if task_key in review_tasks:
            del review_tasks[task_key]

def filter_files_to_analyze(pr_files, max_files):
    """Filter files to prioritize important ones for analysis"""
    # Skip files that are likely not needing review
    filtered_files = []
    skip_patterns = [
        r'\.lock$', r'\.min\.(js|css)$', r'\.(png|jpg|gif|ico|svg)$',
        r'node_modules/', r'vendor/', r'dist/', r'build/'
    ]
    
    # First pass: add high-priority files (source code)
    high_priority_extensions = ['.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.c', '.cpp', '.go']
    
    for file_data in pr_files:
        filename = file_data.get("filename", "")
        
        # Skip certain file types
        if any(re.search(pattern, filename) for pattern in skip_patterns):
            continue
        
        # Prioritize important source code files
        if any(filename.endswith(ext) for ext in high_priority_extensions):
            filtered_files.append(file_data)
    
    # Second pass: add other files if we haven't reached our limit
    if len(filtered_files) < max_files:
        for file_data in pr_files:
            filename = file_data.get("filename", "")
            
            # Skip files already added and files matching skip patterns
            if file_data in filtered_files or any(re.search(pattern, filename) for pattern in skip_patterns):
                continue
                
            filtered_files.append(file_data)
            if len(filtered_files) >= max_files:
                break
    
    return filtered_files[:max_files]

def post_initial_comment(repo_full_name, pr_number, token):
    """Post an initial comment that review is in progress"""
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json"
    }
    
    payload = {
        "body": "🔍 I'm reviewing this PR now. I'll post my complete review shortly..."
    }

    requests.post(
        f"https://api.github.com/repos/{repo_full_name}/issues/{pr_number}/comments",
        headers=headers,
        json=payload
    )

def analyze_file_for_comments(file_data):
    """Analyze a single file and generate specific line comments with GitHub change suggestions"""
    filename = file_data.get("filename")
    patch = file_data.get("patch", "")
    
    # Skip if no patch or file is too large
    if not patch:
        return []
        
    # Skip large patches to avoid timeouts
    if len(patch) > 10000:
        return [{
            "line": "File too large for detailed review",
            "comment": "This file is too large for detailed line-by-line review. Consider breaking down large files into smaller, more focused components."
        }]
    
    # Preparing file context with a more focused prompt
    prompt = f"""You are a code reviewer reviewing file: {filename}

Changes:
```
{patch}
```

Identify up to 2 important issues. For each:
1. Extract the exact problematic line
2. Explain the issue briefly (1-2 sentences)
3. Provide a corrected code line

Format as JSON:
[
  {{
    "line": "exact problematic code line",
    "comment": "brief explanation",
    "suggestion": "corrected code line"
  }}
]

Return [] if no issues found."""

    try:
        # Use a timeout to prevent hanging
        response = anthropic_client.messages.create(
            model="claude-3-5-sonnet-20241022",
            max_tokens=500,  # Reduced token count 
            system="You are a code reviewer. Be concise.",
            messages=[
                {"role": "user", "content": [{"type": "text", "text": prompt}]}
            ]
        )
        
        # Extract and parse the JSON response
        content = response.content[0].text
        
        # Find JSON array in response
        json_match = re.search(r'\[\s*\{.*\}\s*\]', content, re.DOTALL)
        if json_match:
            try:
                return json.loads(json_match.group(0))
            except json.JSONDecodeError:
                print(f"Failed to parse JSON")
                return []
        
        # Empty response
        if "[]" in content:
            return []
            
        # Try to parse whole response
        try:
            return json.loads(content)
        except json.JSONDecodeError:
            return []
            
    except Exception as e:
        print(f"Error analyzing file {filename}: {str(e)}")
        return []

@app.route('/', methods=['GET'])
def hello():
    return Response("hello", status=200)

@app.route('/api/webhook', methods=['POST'])
def webhook_handler():
    """Handle GitHub webhooks - return quickly and process in background"""
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
            
            if not (pr and repo):
                return Response("Missing required data", status=400)
                
            pr_number = pr.get('number')
            repo_full_name = repo.get('full_name')
            
            # Create a task key to avoid duplicate processing
            task_key = f"{repo_full_name}_{pr_number}"
            
            # Only start a new task if one isn't already running for this PR
            if task_key not in review_tasks:
                # Start background thread for processing
                thread = threading.Thread(
                    target=process_pr_review_async,
                    args=(payload,)
                )
                thread.daemon = True  # Thread will exit when main thread exits
                thread.start()
                
                # Store thread in global dict
                review_tasks[task_key] = thread
                
                return Response("PR review started in background", status=202)
            else:
                return Response("PR review already in progress", status=200)
    
    return Response("Event processed", status=200)

# For local development
if __name__ == '__main__':
    app.run(debug=True)
