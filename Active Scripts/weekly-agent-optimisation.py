#!/usr/bin/env python3
"""
Weekly Zendesk Agent Role Optimization Script - GitHub Actions Version
Automatically manages agent roles based on login activity:
- 1+ week inactive: agent → light agent
- 1+ month inactive: agent/light agent → end user
- Protects admins from any changes
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
                wait_time = (2 ** attempt) * 5
                logging.warning(f"Rate limited. Waiting {wait_time} seconds...")
                time.sleep(wait_time)
                continue
            elif e.code in [400, 401, 403, 404, 422]:
                error_body = e.read().decode('utf-8') if e.fp else str(e)
                return e.code, error_body
            else:
                if attempt == max_retries - 1:
                    return e.code, e.read().decode('utf-8') if e.fp else str(e)
                time.sleep(2 ** attempt)
        except Exception as e:
            if attempt == max_retries - 1:
                return 0, str(e)
            time.sleep(2 ** attempt)
    
    return 0, "Max retries exceeded"

class WeeklyAgentOptimizer:
    def __init__(self, dry_run: bool = True):
        self.subdomain = os.getenv('ZD_SUBDOMAIN', 'manualhelp')
        self.email = os.getenv('ZD_EMAIL')
        self.api_token = os.getenv('ZD_API_TOKEN')
        self.dry_run = dry_run
        
        # Set cutoff dates
        self.week_cutoff = datetime.now(timezone.utc) - timedelta(days=7)
        self.month_cutoff = datetime.now(timezone.utc) - timedelta(days=30)
        
        if not all([self.subdomain, self.email, self.api_token]):
            raise ValueError("Missing required environment variables: ZD_SUBDOMAIN, ZD_EMAIL, ZD_API_TOKEN")
        
        auth_string = f"{self.email}/token:{self.api_token}"
        self.auth_header = f"Basic {base64.b64encode(auth_string.encode()).decode()}"
        self.base_url = f"https://{self.subdomain}.zendesk.com/api/v2"
        
        # Get light agent custom role ID
        self.light_agent_role_id = self.get_light_agent_role_id()
        
        logging.info(f"🔧 {'DRY RUN - ' if self.dry_run else ''}WEEKLY AGENT ROLE OPTIMIZATION")
        logging.info(f"🏢 Domain: {self.subdomain}.zendesk.com")
        logging.info(f"📅 Week cutoff: {self.week_cutoff.strftime('%Y-%m-%d %H:%M:%S UTC')}")
        logging.info(f"📅 Month cutoff: {self.month_cutoff.strftime('%Y-%m-%d %H:%M:%S UTC')}")
        logging.info("=" * 80)

    def get_light_agent_role_id(self) -> int:
        """Get the Light agent custom role ID."""
        url = f"{self.base_url}/custom_roles.json"
        status, response = make_api_request(url, auth_header=self.auth_header)
        
        if status != 200:
            raise ValueError(f"Failed to fetch custom roles: {status} - {response}")
        
        data = json.loads(response)
        roles = data.get('custom_roles', [])
        
        # Log all available roles for debugging
        logging.info("🔍 Available custom roles:")
        for role in roles:
            logging.info(f"   - '{role['name']}' (ID: {role['id']})")
        
        # Look for light agent role (case insensitive)
        for role in roles:
            role_name = role['name'].lower().strip()
            if role_name == 'light agent':
                logging.info(f"✅ Found Light agent role: '{role['name']}' (ID: {role['id']})")
                return role['id']
        
        # If exact match fails, try partial matches
        logging.warning("Exact 'Light agent' not found, trying partial matches...")
        for role in roles:
            role_name = role['name'].lower().strip()
            if 'light' in role_name and 'agent' in role_name:
                logging.info(f"✅ Found matching role: '{role['name']}' (ID: {role['id']})")
                return role['id']
        
        # List all available roles for user reference
        available_roles = [f"'{role['name']}' (ID: {role['id']})" for role in roles]
        error_msg = f"Light agent custom role not found! Available roles: {', '.join(available_roles)}"
        raise ValueError(error_msg)

    def get_all_team_members(self) -> List[Dict]:
        """Fetch all team members (agents and admins) efficiently."""
        logging.info("👥 Fetching all team members...")
        all_team_members = []
        
        # Fetch agents and admins separately for efficiency
        for role in ['agent', 'admin']:
            logging.info(f"🔍 Fetching {role}s...")
            url = f"{self.base_url}/users.json?role={role}&page[size]=100"
            page_count = 0
            role_users = []
            
            while url and page_count < 50:  # 50 pages = 5000 users max per role
                page_count += 1
                if page_count % 10 == 0:
                    logging.info(f"  {role}s: Fetched {page_count} pages...")
                
                status, response = make_api_request(url, auth_header=self.auth_header)
                
                if status != 200:
                    logging.error(f"Failed to fetch {role}s: {status} - {response}")
                    break
                    
                data = json.loads(response)
                users = data.get('users', [])
                role_users.extend(users)
                
                # Get next page URL from links
                links = data.get('links', {})
                url = links.get('next')
                
                time.sleep(0.1)  # Rate limiting
            
            logging.info(f"✅ Fetched {len(role_users)} {role}s")
            all_team_members.extend(role_users)
        
        logging.info(f"✅ Total team members fetched: {len(all_team_members)}")
        return all_team_members

    def parse_last_login_date(self, last_login_str: Optional[str]) -> Optional[datetime]:
        """Parse the last_login_at string to datetime."""
        if not last_login_str:
            return None
        
        try:
            clean_date = last_login_str.split('.')[0] + 'Z' if '.' in last_login_str else last_login_str
            return datetime.fromisoformat(clean_date.replace('Z', '+00:00'))
        except (ValueError, AttributeError):
            return None

    def check_agent_ticket_assignments(self, agent_id: int) -> Tuple[int, int, List[str]]:
        """Check how many tickets are assigned to this agent."""
        url = f"{self.base_url}/search.json?query=assignee:{agent_id}%20status<solved"
        status, response = make_api_request(url, auth_header=self.auth_header)
        
        if status == 200:
            data = json.loads(response)
            results = data.get('results', [])
            total_count = data.get('count', 0)
            
            sample_ticket_ids = [str(ticket['id']) for ticket in results[:5]]
            
            # Count recent tickets (last 7 days)
            recent_count = 0
            cutoff_7_days = datetime.now(timezone.utc) - timedelta(days=7)
            
            for ticket in results:
                created_at_str = ticket.get('created_at', '')
                try:
                    created_at = datetime.fromisoformat(created_at_str.replace('Z', '+00:00'))
                    if created_at > cutoff_7_days:
                        recent_count += 1
                except:
                    continue
            
            return total_count, recent_count, sample_ticket_ids
        
        return 0, 0, []

    def analyze_user_activity(self, team_members: List[Dict]) -> Dict[str, List[Dict]]:
        """Analyze team member activity and categorize actions needed."""
        
        logging.info(f"📊 Analyzing {len(team_members)} team members")
        
        results = {
            'week_inactive': [],     # agent → light agent
            'month_inactive': [],    # agent/light agent → end user
            'protected_admins': [],  # admins (no changes)
            'active_users': [],      # no changes needed
            'blocked_users': [],     # have open tickets, can't change
            'never_logged_in': []    # never signed in - skip for safety
        }
        
        for i, user in enumerate(team_members, 1):
            if i % 50 == 0:
                logging.info(f"  Processed {i}/{len(team_members)} team members...")
            
            last_login_str = user.get('last_login_at')
            last_login_date = self.parse_last_login_date(last_login_str)
            
            user_data = {
                'id': user['id'],
                'name': user['name'],
                'email': user['email'],
                'role': user['role'],
                'custom_role_id': user.get('custom_role_id'),
                'last_login_at': last_login_str,
                'last_login_parsed': last_login_date,
                'days_since_login': None,
                'action_type': None,
                'can_convert': False,
                'blocking_reason': None,
                'open_tickets': 0,
                'recent_tickets': 0,
                'sample_ticket_ids': []
            }
            
            # Skip admins completely
            if user['role'] == 'admin':
                user_data['action_type'] = 'protected_admin'
                results['protected_admins'].append(user_data)
                continue
            
            # Calculate days since login
            if last_login_date:
                days_since = (datetime.now(timezone.utc) - last_login_date).days
                user_data['days_since_login'] = days_since
            else:
                user_data['days_since_login'] = 'Never'
                days_since = None  # Keep as None to distinguish from real dates
            
            # Determine action needed based on activity
            if days_since is not None:
                if days_since >= 30:
                    # Month inactive: convert to end user
                    user_data['action_type'] = 'month_inactive'
                elif days_since >= 7:
                    # Week inactive: convert to light agent (only if currently full agent)
                    if user['role'] == 'agent' and not user.get('custom_role_id'):
                        user_data['action_type'] = 'week_inactive'
                    else:
                        user_data['action_type'] = 'active'
                else:
                    user_data['action_type'] = 'active'
            else:
                # Never logged in - SKIP (don't convert new team members who haven't logged in yet)
                user_data['action_type'] = 'never_logged_in'
                user_data['blocking_reason'] = 'Never signed in - may be new team member'
            
            # Check ticket assignments for users that need changes
            if user_data['action_type'] in ['week_inactive', 'month_inactive']:
                open_count, recent_count, sample_tickets = self.check_agent_ticket_assignments(user['id'])
                
                user_data['open_tickets'] = open_count
                user_data['recent_tickets'] = recent_count
                user_data['sample_ticket_ids'] = sample_tickets
                
                # Determine if user can be safely converted
                if open_count > 0:
                    user_data['can_convert'] = False
                    user_data['blocking_reason'] = f"{open_count} open tickets assigned"
                    results['blocked_users'].append(user_data)
                elif recent_count > 5:  # Still handling recent tickets
                    user_data['can_convert'] = False
                    user_data['blocking_reason'] = f"{recent_count} recent tickets (still active)"
                    results['blocked_users'].append(user_data)
                else:
                    user_data['can_convert'] = True
                    if user_data['action_type'] == 'week_inactive':
                        results['week_inactive'].append(user_data)
                    else:
                        results['month_inactive'].append(user_data)
            elif user_data['action_type'] == 'never_logged_in':
                results['never_logged_in'].append(user_data)
            else:
                results['active_users'].append(user_data)
        
        # Log summary
        logging.info(f"\n📊 ANALYSIS SUMMARY:")
        logging.info(f"   Agents to convert to light agents: {len(results['week_inactive'])}")
        logging.info(f"   Agents to convert to end users: {len(results['month_inactive'])}")
        logging.info(f"   Blocked by tickets/activity: {len(results['blocked_users'])}")
        logging.info(f"   Protected admins: {len(results['protected_admins'])}")
        logging.info(f"   Never logged in (skipped for safety): {len(results['never_logged_in'])}")
        logging.info(f"   Active users (no changes): {len(results['active_users'])}")
        
        return results

    def convert_agent_to_light_agent(self, user_id: int) -> Tuple[bool, str]:
        """Convert agent to light agent role."""
        if self.dry_run:
            return True, "DRY RUN - Would convert to light agent"
        
        url = f"{self.base_url}/users/{user_id}.json"
        update_data = {
            "user": {
                "custom_role_id": self.light_agent_role_id
            }
        }
        
        data = json.dumps(update_data).encode('utf-8')
        status, response = make_api_request(url, method='PUT', data=data, auth_header=self.auth_header)
        
        if status == 200:
            return True, "Successfully converted to light agent"
        else:
            return False, f"Error {status}: {response}"

    def convert_agent_to_end_user(self, user_id: int) -> Tuple[bool, str]:
        """Convert agent to end user."""
        if self.dry_run:
            return True, "DRY RUN - Would convert to end user"
        
        url = f"{self.base_url}/users/{user_id}.json"
        update_data = {
            "user": {
                "role": "end-user",
                "custom_role_id": None
            }
        }
        
        data = json.dumps(update_data).encode('utf-8')
        status, response = make_api_request(url, method='PUT', data=data, auth_header=self.auth_header)
        
        if status == 200:
            return True, "Successfully converted to end user"
        else:
            return False, f"Error {status}: {response}"

    def execute_optimizations(self, analysis_results: Dict[str, List[Dict]]) -> List[Dict]:
        """Execute the role optimizations."""
        
        mode_text = "SIMULATING" if self.dry_run else "EXECUTING"
        logging.info(f"\n🔄 {mode_text} ROLE OPTIMIZATIONS...")
        logging.info("-" * 80)
        
        conversion_results = []
        total_successful = 0
        total_failed = 0
        
        # Convert agents to light agents (week inactive)
        week_inactive = analysis_results['week_inactive']
        if week_inactive:
            logging.info(f"🔸 Converting {len(week_inactive)} agents to light agents...")
            
            for i, user in enumerate(week_inactive, 1):
                logging.info(f"  [{i}/{len(week_inactive)}] {user['name']} ({user['email']})...")
                
                success, message = self.convert_agent_to_light_agent(user['id'])
                
                result = {
                    'user_id': user['id'],
                    'name': user['name'],
                    'email': user['email'],
                    'from_role': user['role'],
                    'to_role': 'agent (light)',
                    'action_type': 'week_inactive',
                    'days_since_login': user['days_since_login'],
                    'success': success,
                    'message': message,
                    'timestamp': datetime.now().isoformat()
                }
                
                conversion_results.append(result)
                
                if success:
                    total_successful += 1
                    logging.info(f"    ✅ {message}")
                else:
                    total_failed += 1
                    logging.error(f"    ❌ {message}")
                
                if not self.dry_run:
                    time.sleep(0.5)
        
        # Convert agents to end users (month inactive)
        month_inactive = analysis_results['month_inactive']
        if month_inactive:
            logging.info(f"🔸 Converting {len(month_inactive)} agents to end users...")
            
            for i, user in enumerate(month_inactive, 1):
                logging.info(f"  [{i}/{len(month_inactive)}] {user['name']} ({user['email']})...")
                
                success, message = self.convert_agent_to_end_user(user['id'])
                
                result = {
                    'user_id': user['id'],
                    'name': user['name'],
                    'email': user['email'],
                    'from_role': user['role'],
                    'to_role': 'end-user',
                    'action_type': 'month_inactive',
                    'days_since_login': user['days_since_login'],
                    'success': success,
                    'message': message,
                    'timestamp': datetime.now().isoformat()
                }
                
                conversion_results.append(result)
                
                if success:
                    total_successful += 1
                    logging.info(f"    ✅ {message}")
                else:
                    total_failed += 1
                    logging.error(f"    ❌ {message}")
                
                if not self.dry_run:
                    time.sleep(0.5)
        
        logging.info(f"\n📊 {mode_text.upper()} SUMMARY:")
        logging.info(f"   ✅ Successful conversions: {total_successful}")
        logging.info(f"   ❌ Failed conversions: {total_failed}")
        logging.info(f"   📋 Total processed: {len(conversion_results)}")
        
        return conversion_results

    def export_results(self, analysis_results: Dict[str, List[Dict]], conversion_results: List[Dict]) -> str:
        """Export all results to CSV."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"weekly_agent_optimization_{'dryrun' if self.dry_run else 'results'}_{timestamp}.csv"
        
        # Combine all users for export
        all_users = []
        for category, users in analysis_results.items():
            for user in users:
                user['category'] = category
                all_users.append(user)
        
        # Create results lookup
        results_dict = {r['user_id']: r for r in conversion_results}
        
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = [
                'user_id', 'name', 'email', 'role', 'custom_role_id', 'category',
                'last_login_at', 'days_since_login', 'action_type', 'can_convert',
                'blocking_reason', 'open_tickets', 'recent_tickets', 'sample_ticket_ids',
                'conversion_success', 'conversion_message', 'timestamp'
            ]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            
            for user in all_users:
                result = results_dict.get(user['id'], {})
                
                row = {
                    'user_id': user['id'],
                    'name': user['name'],
                    'email': user['email'],
                    'role': user['role'],
                    'custom_role_id': user.get('custom_role_id', ''),
                    'category': user['category'],
                    'last_login_at': user.get('last_login_at', ''),
                    'days_since_login': user.get('days_since_login', ''),
                    'action_type': user.get('action_type', ''),
                    'can_convert': user.get('can_convert', ''),
                    'blocking_reason': user.get('blocking_reason', ''),
                    'open_tickets': user.get('open_tickets', ''),
                    'recent_tickets': user.get('recent_tickets', ''),
                    'sample_ticket_ids': ', '.join(user.get('sample_ticket_ids', [])),
                    'conversion_success': result.get('success', ''),
                    'conversion_message': result.get('message', ''),
                    'timestamp': result.get('timestamp', '')
                }
                writer.writerow(row)
        
        logging.info(f"📁 Results exported to: {filename}")
        return filename

def main():
    parser = argparse.ArgumentParser(description='Weekly Zendesk Agent Role Optimization')
    parser.add_argument('--live', action='store_true', help='Execute changes (default is dry run)')
    parser.add_argument('--log-level', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'], 
                       default='INFO', help='Set logging level')
    
    args = parser.parse_args()
    
    # Setup logging
    log_filename = setup_logging()
    logging.getLogger().setLevel(getattr(logging, args.log_level))
    
    dry_run = not args.live
    
    try:
        logging.info("🔧 WEEKLY ZENDESK AGENT ROLE OPTIMIZATION")
        logging.info("=" * 80)
        
        optimizer = WeeklyAgentOptimizer(dry_run=dry_run)
        
        # Step 1: Get all team members (agents and admins)
        all_team_members = optimizer.get_all_team_members()
        
        if not all_team_members:
            logging.error("❌ No team members found!")
            return 1
        
        # Step 2: Analyze team member activity
        analysis_results = optimizer.analyze_user_activity(all_team_members)
        
        # Step 3: Execute optimizations
        conversion_results = optimizer.execute_optimizations(analysis_results)
        
        # Step 4: Export results
        results_file = optimizer.export_results(analysis_results, conversion_results)
        
        # Step 5: Final summary
        total_changes = len([r for r in conversion_results if r['success']])
        week_changes = len([r for r in conversion_results if r['action_type'] == 'week_inactive' and r['success']])
        month_changes = len([r for r in conversion_results if r['action_type'] == 'month_inactive' and r['success']])
        
        logging.info(f"\n🎯 {'DRY RUN' if dry_run else 'OPTIMIZATION'} COMPLETE!")
        
        if dry_run:
            logging.info(f"📋 Would convert {week_changes} agents to light agents")
            logging.info(f"📋 Would convert {month_changes} agents to end users")
            logging.info(f"💰 Potential savings: {total_changes} licenses optimized")
            logging.info(f"🚀 Run with --live to execute changes")
        else:
            logging.info(f"✅ {week_changes} agents converted to light agents")
            logging.info(f"✅ {month_changes} agents converted to end users")
            logging.info(f"💰 Actual savings: {total_changes} licenses optimized")
        
        logging.info(f"📁 Detailed results: {results_file}")
        logging.info(f"📁 Log file: {log_filename}")
        
        return 0
        
    except Exception as e:
        logging.error(f"❌ Weekly optimization failed: {e}")
        return 1

if __name__ == "__main__":
    exit(main())
