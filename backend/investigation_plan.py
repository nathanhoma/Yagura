"""Evidence-backed, persistent host queue for an operator's investigation goal."""

import re


WEB = re.compile(r'web|ウェブ|http|site|サイト', re.I)
ACCESS = re.compile(r'initial access|イニシャルアクセス|侵入|foothold', re.I)
WEB_PORTS = {80, 443, 8000, 8080, 8443, 8888}
ACCESS_PORTS = {21, 22, 80, 443, 445, 3389, 8000, 8080, 8443}


def success_criteria(goal):
    if ACCESS.search(goal):
        return 'Initial access is verified only by saved evidence of an authorized foothold; service banners and version matches are leads, not success.'
    return 'Answer the operator goal with saved, cited evidence; state unresolved points when checks do not verify it.'


def refresh(plan, document, flags=()):
    """Re-rank remaining approved candidates after each saved observation."""
    services = {}
    for finding in document.get('findings', []):
        if finding.get('kind') == 'service' and finding.get('state') == 'open':
            services.setdefault(finding.get('hostId'), []).append(finding)
    flagged = {item.get('hostId') for item in flags}
    for row in plan['candidates']:
        observed = services.get(row['hostId'], [])
        ports = {item.get('port') for item in observed}
        signals = []
        if row['hostId'] in flagged:
            signals.append('Saved review lead')
        if WEB.search(plan['goal']) and ports & WEB_PORTS:
            signals.append('Observed web service')
        elif ACCESS.search(plan['goal']) and ports & ACCESS_PORTS:
            signals.append('Observed access-facing service')
        if observed:
            signals.append(f'{len(observed)} observed open services')
        row['signals'] = signals
        row['score'] = (20 if row['hostId'] in flagged else 0) + (10 if len(signals) > 1 else 0) + min(len(observed), 9)
        row['openQuestion'] = ('Which check would verify the goal from the saved service evidence?'
                               if observed else 'Which services, if any, are reachable on this approved host?')
    pending = sorted((row for row in plan['candidates'] if row['status'] == 'pending'),
                     key=lambda row: (-row['score'], row['name'], row['ip']))
    plan['nextHostId'] = pending[0]['hostId'] if pending else None
    plan['reviewedHosts'] = sum(row['status'] in ('reviewed', 'blocked') for row in plan['candidates'])
    plan['openQuestions'] = [row['openQuestion'] for row in pending[:3]]
    plan['nextStep'] = (f"Investigate {pending[0]['name']}: {pending[0]['openQuestion']}"
                        if pending else 'Assess saved evidence against the success criterion.')
    return plan


def create(goal, hosts, document, flags=()):
    plan = {'goal': goal, 'successCriterion': success_criteria(goal), 'status': 'in-progress',
            'candidates': [dict(hostId=host['id'], ip=host['ip'], name=host.get('name') or host['ip'],
                                status='pending', checks=0, evidenceIds=[], signals=[], score=0,
                                openQuestion='') for host in hosts],
            'nextHostId': None, 'reviewedHosts': 0, 'openQuestions': [],
            'nextStep': '', 'completedSteps': []}
    return refresh(plan, document, flags)
