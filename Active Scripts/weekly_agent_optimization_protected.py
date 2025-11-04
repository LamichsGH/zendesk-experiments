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
                    'last_login_at': user.get('last_login_at'),
                    'active': user.get('active', True),
                    'suspended': user.get('suspended', False),
                    'created_at': user.get('created_at')
                }
                
                # Check if this is a protected TRT clinician
                if user_data['email'] in PROTECTED_TRT_CLINICIANS:
                    user_data['action_type'] = 'trt_clinician_protected'
                    user_data['blocking_reason'] = 'TRT clinician - protected from role changes'
                    results['errors'].append(user_data)
                    logging.info(f"🛡️  Protected TRT clinician: {user_data['name']} ({user_data['email']})")
                    continue
                
                # Skip if suspended or inactive
                if user_data['suspended'] or not user_data['active']:
                    user_data['action_type'] = 'suspended_or_inactive'
                    user_data['blocking_reason'] = 'User is suspended or inactive'
                    results['errors'].append(user_data)
                    continue
                
                # Skip admins
                if user_data['role'] == 'admin':
                    user_data['action_type'] = 'admin_protected'
                    user_data['blocking_reason'] = 'Admin role - protected from changes'
                    results['errors'].append(user_data)
                    continue
                
                # Parse last login date
                if user_data['last_login_at']:
                    last_login = datetime.fromisoformat(user_data['last_login_at'].replace('Z', '+00:00'))
                    days_since = (datetime.now(timezone.utc) - last_login).days
                    user_data['days_since_login'] = days_since
                else:
                    user_data['days_since_login'] = 'Never'
                    days_since = None  # Keep as None to distinguish from real dates
                
                # Check for assigned tickets
                assigned_tickets = self.get_assigned_tickets_count(user_data['id'])
                user_data['assigned_tickets'] = assigned_tickets
                
                if assigned_tickets > 0:
                    user_data['action_type'] = 'has_tickets'
                    user_data['blocking_reason'] = f'Has {assigned_tickets} assigned tickets'
                    results['errors'].append(user_data)
                    continue
                
                # Categorize based on activity - 4 weeks and 8 weeks
                if days_since is not None:
                    if days_since >= 56:  # 8+ weeks inactive
                        if user_data['role'] in ['agent', 'end-user']:
                            user_data['action_type'] = 'month_inactive'
                            user_data['recommended_action'] = 'Convert to end-user'
                            results['month_inactive'].append(user_data)
                        else:
                            user_data['action_type'] = 'already_converted'
                            user_data['blocking_reason'] = f'Already has role: {user_data["role"]}'
                            results['errors'].append(user_data)
                    elif days_since >= 28:  # 4+ weeks inactive
                        if user_data['role'] == 'agent':
                            user_data['action_type'] = 'week_inactive'
                            user_data['recommended_action'] = 'Convert to light agent'
                            results['week_inactive'].append(user_data)
                        else:
                            user_data['action_type'] = 'already_light_or_end_user'
                            user_data['blocking_reason'] = f'Already has role: {user_data["role"]}'
                            results['errors'].append(user_data)
                    else:  # Active
                        user_data['action_type'] = 'active'
                        results['active'].append(user_data)
                else:
                    # Never logged in - SKIP (don't convert new team members who haven't logged in yet)
                    user_data['action_type'] = 'never_logged_in'
                    user_data['blocking_reason'] = 'Never signed in - may be new team member'
                    results['never_logged_in'].append(user_data)
                
            except Exception as e:
                error_data = {
                    'id': user.get('id', 'unknown'),
                    'name': user.get('name', 'unknown'),
                    'email': user.get('email', 'unknown'),
                    'error': str(e),
                    'action_type': 'error'
                }
                results['errors'].append(error_data)
                logging.error(f"Error processing user {user.get('name', 'unknown')}: {e}")
        
        # Log summary - Updated labels to reflect 4 weeks and 8 weeks
        logging.info("📈 Activity Analysis Summary:")
        logging.info(f"   🟢 Active (< 28 days): {len(results['active'])}")
        logging.info(f"   🟡 Four weeks inactive (28-55 days): {len(results['week_inactive'])}")
        logging.info(f"   🔴 Eight weeks inactive (56+ days): {len(results['month_inactive'])}")
        logging.info(f"   ⚪ Never logged in (skipped for safety): {len(results['never_logged_in'])}")
        logging.info(f"   ❌ Errors/Blocked: {len(results['errors'])}")
        
        return results

    def convert_agent_to_light_agent(self, user_id: int, user_name: str) -> bool:
        """Convert an agent to light agent (custom role)."""
        if self.dry_run:
            logging.info(f"🔄 [DRY RUN] Would convert {user_name} (ID: {user_id}) to light agent")
            return True
        
        # Step 1: Convert to end-user (system role)
        url = f"{self.base_url}/users/{user_id}.json"
        update_data = {
            "user": {
                "role": "end-user"
            }
        }
        
        data = json.dumps(update_data).encode('utf-8')
        status, response = make_api_request(url, method='PUT', data=data, auth_header=self.auth_header)
        
        if status == 200:
            logging.info(f"✅ Step 1: Converted {user_name} to end-user")
        else:
            logging.error(f"❌ Failed to convert {user_name} to end-user: {status} - {response}")
            return False
        
        # Step 2: Assign Light agent custom role
        url = f"{self.base_url}/users/{user_id}.json"
        update_data = {
            "user": {
                "custom_role_id": self.light_agent_role_id
            }
        }
        
        data = json.dumps(update_data).encode('utf-8')
        status, response = make_api_request(url, method='PUT', data=data, auth_header=self.auth_header)
        
        if status == 200:
            logging.info(f"✅ Step 2: Assigned Light agent role to {user_name}")
            return True
        else:
            logging.error(f"❌ Failed to assign Light agent role to {user_name}: {status} - {response}")
            return False

    def convert_user_to_end_user(self, user_id: int, user_name: str) -> bool:
        """Convert a user to end-user."""
        if self.dry_run:
            logging.info(f"🔄 [DRY RUN] Would convert {user_name} (ID: {user_id}) to end-user")
            return True
        
        url = f"{self.base_url}/users/{user_id}.json"
        update_data = {
            "user": {
                "role": "end-user",
                "custom_role_id": None  # Remove any custom role
            }
        }
        
        data = json.dumps(update_data).encode('utf-8')
        status, response = make_api_request(url, method='PUT', data=data, auth_header=self.auth_header)
        
        if status == 200:
            logging.info(f"✅ Converted {user_name} to end-user")
            return True
        else:
            logging.error(f"❌ Failed to convert {user_name} to end-user: {status} - {response}")
            return False

    def save_results_to_csv(self, analysis_results: Dict, filename: str):
        """Save analysis results to CSV file."""
        all_users = []
        
        # Combine all categories
        for category, users in analysis_results.items():
            if isinstance(users, list):
                for user in users:
                    user_record = user.copy()
                    user_record['category'] = category
                    all_users.append(user_record)
        
        if not all_users:
            logging.warning("No users to save to CSV")
            return
        
        # Get all possible fields
        all_fields = set()
        for user in all_users:
            all_fields.update(user.keys())
        
        fieldnames = sorted(all_fields)
        
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(all_users)
        
        logging.info(f"📄 Results saved to {filename}")

    def run_optimization(self):
        """Run the complete optimization process."""
        try:
            # Get all team members
            team_members = self.get_all_team_members()
            
            # Analyze activity
            analysis_results = self.analyze_user_activity(team_members)
            
            # Save analysis results
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            analysis_file = f"agent_analysis_{timestamp}.csv"
            self.save_results_to_csv(analysis_results, analysis_file)
            
            # Process conversions
            success_count = 0
            error_count = 0
            
            # Convert week-inactive agents to light agents
            logging.info("🔄 Converting four-week-inactive agents to light agents...")
            for user in analysis_results['week_inactive']:
                if self.convert_agent_to_light_agent(user['id'], user['name']):
                    success_count += 1
                else:
                    error_count += 1
            
            # Convert month-inactive users to end-users
            logging.info("🔄 Converting eight-week-inactive users to end-users...")
            for user in analysis_results['month_inactive']:
                if self.convert_user_to_end_user(user['id'], user['name']):
                    success_count += 1
                else:
                    error_count += 1
            
            # Final summary
            logging.info("=" * 80)
            logging.info(f"🎯 OPTIMIZATION COMPLETE!")
            logging.info(f"✅ Successful conversions: {success_count}")
            logging.info(f"❌ Failed conversions: {error_count}")
            logging.info(f"📊 Analysis saved to: {analysis_file}")
            
            if self.dry_run:
                logging.info("🔍 This was a DRY RUN - no actual changes were made")
            
            return {
                'success_count': success_count,
                'error_count': error_count,
                'analysis_file': analysis_file,
                'analysis_results': analysis_results
            }
            
        except Exception as e:
            logging.error(f"❌ Optimization failed: {e}")
            raise

def main():
    """Main function."""
    parser = argparse.ArgumentParser(description='Weekly Zendesk Agent Role Optimization')
    parser.add_argument('--dry-run', action='store_true', default=True,
                        help='Run in dry-run mode (default: True)')
    parser.add_argument('--execute', action='store_true',
                        help='Execute actual changes (overrides dry-run)')
    parser.add_argument('--log-level', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
                        default='INFO', help='Set logging level')
    
    args = parser.parse_args()
    
    # Setup logging
    log_file = setup_logging()
    
    # Set log level
    logging.getLogger().setLevel(getattr(logging, args.log_level))
    
    # Determine if this is a dry run
    dry_run = args.dry_run and not args.execute
    
    logging.info(f"🚀 Starting Weekly Agent Role Optimization")
    logging.info(f"📝 Log file: {log_file}")
    logging.info(f"🔧 Mode: {'DRY RUN' if dry_run else 'EXECUTE'}")
    
    try:
        optimizer = WeeklyAgentOptimizer(dry_run=dry_run)
        results = optimizer.run_optimization()
        
        logging.info("🎉 Script completed successfully!")
        return 0
        testing testing
    except Exception as e:
        logging.error(f"💥 Script failed: {e}")
        return 1

if __name__ == "__main__":
    exit(main())
