#!/usr/bin/env python3
"""
Weekly Zendesk Agent Role Optimization Script - GitHub Actions Fixed Version
Automatically manages agent roles based on login activity:
- 4+ weeks inactive: agent → light agent
- 8+ weeks inactive: agent/light agent → end user
- Protects admins from any changes
- Protects TRT clinicians from any changes
- SAFE: Never converts agents who have never logged in
"""

import os
import json
import csv
import logging
from datetime import datetime, timezone, timedelta
import urllib.request
import urllib.error
import base64
import time
from typing import Dict, List, Tuple, Optional
import argparse

# Protected TRT clinicians - never change their roles
PROTECTED_TRT_CLINICIANS = {
    'whitney.abiodun@manual.co',
    'chichi.mumba@manual.co', 
    'dawn@manual.co',
    'katej@manual.co',
    'rana@manual.co'
}

def setup_logging():
    """Setup logging for the script."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_filename = f"weekly_agent_optimization_{timestamp}.log"
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_filename),
            logging.StreamHandler()
        ]
    )
    return log_filename

def make_api_request(url: str, method: str = 'GET', data: bytes = None, auth_header: str = '', max_retries: int = 3) -> Tuple[int, str]:
    """Make an API request with retries and rate limiting."""
    for attempt in range(max_retries):
        try:
            request = urllib.request.Request(url, data=data, method=method)
            request.add_header('Authorization', auth_header)
            request.add_header('Content-Type', 'application/json')
            
            with urllib.request.urlopen(request) as response:
                return response.getcode(), response.read().decode('utf-8')
                
        except urllib.error.HTTPError as e:
            if e.code == 429:  # Rate limited
                sleep_time = 2 ** attempt
                logging.warning(f"Rate limited (429), retrying in {sleep_time} seconds...")
                time.sleep(sleep_time)
                continue
            else:
                return e.code, e.read().decode('utf-8')
        except Exception as e:
            if attempt == max_retries - 1:
                return 0, str(e)
            time.sleep(1)
    
    return 0, "Max retries exceeded"

class WeeklyAgentOptimizer:
    def __init__(self, dry_run: bool = True):
        # Enhanced environment variable debugging
        logging.info("🔍 Environment Variable Debug:")
        
        # Get environment variables with debugging
        self.subdomain = os.getenv('ZD_SUBDOMAIN', 'manualhelp')
        self.email = os.getenv('ZD_EMAIL')
        self.api_token = os.getenv('ZD_API_TOKEN')
        
        # Debug environment variables
        logging.info(f"   ZD_SUBDOMAIN: {'✅ SET' if self.subdomain else '❌ NOT SET'} (value: {self.subdomain})")
        logging.info(f"   ZD_EMAIL: {'✅ SET' if self.email else '❌ NOT SET'} (value: {self.email})")
        logging.info(f"   ZD_API_TOKEN: {'✅ SET' if self.api_token else '❌ NOT SET'} (length: {len(self.api_token) if self.api_token else 0})")
        
        # Check if running in GitHub Actions
        if os.getenv('GITHUB_ACTIONS'):
            logging.info("🎭 Running in GitHub Actions environment")
            # Show all ZD_ environment variables
            zd_vars = {k: v for k, v in os.environ.items() if k.startswith('ZD_')}
            logging.info(f"   All ZD_ environment variables: {list(zd_vars.keys())}")
        else:
            logging.info("💻 Running in local environment")
        
        self.dry_run = dry_run
        
        # Validate environment variables
        missing_vars = []
        if not self.subdomain:
            missing_vars.append('ZD_SUBDOMAIN')
        if not self.email:
            missing_vars.append('ZD_EMAIL')
        if not self.api_token:
            missing_vars.append('ZD_API_TOKEN')
        
        if missing_vars:
            error_msg = f"Missing required environment variables: {', '.join(missing_vars)}"
            logging.error(f"❌ {error_msg}")
            raise ValueError(error_msg)
        
        # Setup authentication
        auth_string = f"{self.email}/token:{self.api_token}"
        self.auth_header = f"Basic {base64.b64encode(auth_string.encode()).decode()}"
        self.base_url = f"https://{self.subdomain}.zendesk.com/api/v2"
        
        # Test API connection immediately
        logging.info("🧪 Testing API connection...")
        test_url = f"{self.base_url}/users/me.json"
        status, response = make_api_request(test_url, auth_header=self.auth_header)
        if status == 200:
            data = json.loads(response)
            user = data.get('user', {})
            logging.info(f"✅ API connection successful!")
            logging.info(f"   Authenticated as: {user.get('name', 'Unknown')} ({user.get('email', 'Unknown')})")
            logging.info(f"   Role: {user.get('role', 'Unknown')}")
            logging.info(f"   User ID: {user.get('id', 'Unknown')}")
        else:
            error_msg = f"API connection failed: {status} - {response}"
            logging.error(f"❌ {error_msg}")
            raise ValueError(error_msg)
        
        # Test custom roles endpoint specifically
        logging.info("🧪 Testing custom roles endpoint...")
        custom_roles_url = f"{self.base_url}/custom_roles.json"
        status, response = make_api_request(custom_roles_url, auth_header=self.auth_header)
        if status == 200:
            logging.info(f"✅ Custom roles endpoint works!")
        else:
            logging.error(f"❌ Custom roles endpoint failed: {status} - {response}")
            logging.error(f"   This suggests API token lacks admin permissions for custom roles")
            logging.error(f"   Current user role: {user.get('role', 'Unknown')}")
            
            # Try alternative approach - hardcode the Light agent role ID
            logging.info("🔄 Using hardcoded Light agent role ID as fallback...")
            self.light_agent_role_id = 6415937321620  # The ID we know works
            logging.info(f"✅ Using Light agent role ID: {self.light_agent_role_id}")
            
            # Skip the get_light_agent_role_id call and continue
            self.week_cutoff = datetime.now(timezone.utc) - timedelta(days=28)  # 4 weeks
            self.month_cutoff = datetime.now(timezone.utc) - timedelta(days=56)  # 8 weeks
            
            logging.info(f"🔧 {'DRY RUN - ' if self.dry_run else ''}WEEKLY AGENT ROLE OPTIMIZATION")
            logging.info(f"🏢 Domain: {self.subdomain}.zendesk.com")
            logging.info(f"📅 Four-week cutoff: {self.week_cutoff.strftime('%Y-%m-%d %H:%M:%S UTC')}")
            logging.info(f"📅 Eight-week cutoff: {self.month_cutoff.strftime('%Y-%m-%d %H:%M:%S UTC')}")
            logging.info(f"🛡️  Protected TRT clinicians: {len(PROTECTED_TRT_CLINICIANS)} accounts")
            logging.info("=" * 80)
            return  # Skip the normal initialization
        
        # Get light agent custom role ID
        self.light_agent_role_id = self.get_light_agent_role_id()
        
        # Set up time calculations - 4 weeks and 8 weeks
        self.week_cutoff = datetime.now(timezone.utc) - timedelta(days=28)  # 4 weeks
        self.month_cutoff = datetime.now(timezone.utc) - timedelta(days=56)  # 8 weeks
        
        logging.info(f"🔧 {'DRY RUN - ' if self.dry_run else ''}WEEKLY AGENT ROLE OPTIMIZATION")
        logging.info(f"🏢 Domain: {self.subdomain}.zendesk.com")
        logging.info(f"📅 Four-week cutoff: {self.week_cutoff.strftime('%Y-%m-%d %H:%M:%S UTC')}")
        logging.info(f"📅 Eight-week cutoff: {self.month_cutoff.strftime('%Y-%m-%d %H:%M:%S UTC')}")
        logging.info(f"🛡️  Protected TRT clinicians: {len(PROTECTED_TRT_CLINICIANS)} accounts")
        logging.info("=" * 80)

    def get_light_agent_role_id(self) -> int:
        """Get the Light agent custom role ID."""
        logging.info("🔍 Fetching Light agent custom role ID...")
        url = f"{self.base_url}/custom_roles.json"
        status, response = make_api_request(url, auth_header=self.auth_header)
        
        if status != 200:
            error_msg = f"Failed to fetch custom roles: {status} - {response}"
            logging.error(f"❌ {error_msg}")
            raise ValueError(error_msg)
        
        data = json.loads(response)
        roles = data.get('custom_roles', [])
        
        # Log all available roles for debugging
        logging.info("🔍 Available custom roles:")
        for role in roles:
            logging.info(f"   - '{role['name']}' (ID: {role['id']})")
        
        # Find Light agent role (case insensitive)
        for role in roles:
            if role['name'].lower() == 'light agent':
                logging.info(f"✅ Found Light agent role: '{role['name']}' (ID: {role['id']})")
                return role['id']
        
        raise ValueError("Light agent custom role not found!")

    def _fetch_paginated_users(self, url: str, user_type: str) -> List[Dict]:
        """Fetch all users using cursor pagination with safety limits."""
        all_users = []
        page_count = 0
        max_pages = 50  # Safety limit to prevent infinite loops
        
        # Convert to cursor pagination if not already
        if 'page[size]' not in url:
            separator = '&' if '?' in url else '?'
            url = f"{url}{separator}page[size]=100"
        
        while url and page_count < max_pages:
            page_count += 1
            if page_count % 5 == 0:
                logging.info(f"  {user_type}: Fetched {page_count} pages...")
            
            status, response = make_api_request(url, auth_header=self.auth_header)
            
            if status != 200:
                logging.error(f"Failed to fetch {user_type} page {page_count}: {status} - {response}")
                break
            
            data = json.loads(response)
            
            # Handle both 'users' and user_type keys
            users_key = user_type if user_type in data else 'users'
            users = data.get(users_key, [])
            
            # Break if we get empty page
            if not users:
                logging.info(f"  {user_type}: Empty page {page_count}, stopping")
                break
                
            all_users.extend(users)
            
            # Use cursor pagination next page (preferred) or fallback to offset
            meta = data.get('meta', {})
            links = data.get('links', {})
            
            if links.get('next'):
                # Cursor pagination
                has_more = meta.get('has_more', True)
                if not has_more:
                    logging.info(f"  {user_type}: has_more=false, stopping")
                    break
                url = links['next']
            else:
                # Fallback to offset pagination
                url = data.get('next_page')
                if not url:
                    logging.info(f"  {user_type}: No next_page, stopping")
                    break
            
            # Rate limiting
            time.sleep(0.1)
        
        if page_count >= max_pages:
            logging.warning(f"⚠️  {user_type}: Hit safety limit of {max_pages} pages!")
        
        logging.info(f"✅ Fetched {len(all_users)} {user_type} from {page_count} pages")
        return all_users

    def get_all_team_members(self) -> List[Dict]:
        """Fetch team members using working API endpoints (avoiding broken custom role pagination)."""
        logging.info("👥 Fetching team members using system roles + deduplication...")
        all_team_members = []
        
        # Use system roles which have working pagination
        logging.info("🔍 Fetching system agents...")
        agents_url = f"{self.base_url}/users.json?role=agent&page[size]=100"
        agents = self._fetch_paginated_users(agents_url, "agents")
        all_team_members.extend(agents)
        
        logging.info("🔍 Fetching system admins...")
        admins_url = f"{self.base_url}/users.json?role=admin&page[size]=100"
        admins = self._fetch_paginated_users(admins_url, "admins")
        all_team_members.extend(admins)
        
        # Get end-users who have custom roles (team members)
        logging.info("🔍 Fetching end-users with custom roles...")
        end_users_url = f"{self.base_url}/users.json?role=end-user&page[size]=100"
        end_users = self._fetch_paginated_users(end_users_url, "end-users")
        
        # Filter end-users to only those with custom roles (team members)
        team_end_users = [user for user in end_users if user.get('custom_role_id')]
        logging.info(f"   Found {len(team_end_users)} end-users with custom roles (team members)")
        all_team_members.extend(team_end_users)
        
        # Remove duplicates (in case someone appears in multiple queries)
        seen_ids = set()
        unique_team_members = []
        for user in all_team_members:
            user_id = user.get('id')
            if user_id not in seen_ids:
                seen_ids.add(user_id)
                unique_team_members.append(user)
        
        total_fetched = len(unique_team_members)
        logging.info(f"✅ Total unique team members: {total_fetched}")
        
        if abs(total_fetched - 466) <= 10:  # Allow some variance
            logging.info("🎯 SUCCESS: Team count is close to expected 466!")
        else:
            logging.warning(f"⚠️  Expected ~466, got {total_fetched}")
        
        return unique_team_members

    def get_assigned_tickets_count(self, agent_id: int) -> int:
        """Check how many tickets are assigned to this agent."""
        url = f"{self.base_url}/search.json?query=assignee:{agent_id}%20status<solved"
        status, response = make_api_request(url, auth_header=self.auth_header)
        
        if status == 200:
            data = json.loads(response)
            return data.get('count', 0)
        else:
            logging.warning(f"Could not fetch ticket count for agent {agent_id}: {status}")
            return 0

    def analyze_user_activity(self, team_members: List[Dict]) -> Dict:
        """Analyze user activity and categorize users."""
        logging.info("📊 Analyzing user activity...")
        
        results = {
            'active': [],
            'week_inactive': [],
            'month_inactive': [],
            'never_logged_in': [],
            'errors': []
        }
        
        for user in team_members:
            try:
                user_data = {
                    'id': user['id'],
                    'name': user['name'],
                    'email': user['email'],
                    'role': user['role'],
                    'custom_role_id': user.get('custom_role_id'),
