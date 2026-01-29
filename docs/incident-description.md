
Consider incident number <incident-id>. 

Return a paragraph named "Incident Metadata"
Retrieve and list these incident's metadata: 
- Title
- Description
- Status
- Severity
- Priority assessment (if available)
- Classification
- Determination
- Created Date
- First Activity Date
- Last Updated Date
- Assigned To
- MITRE Categories
- Tags

Then return a paragraph named "Incident Alerts".
Retrieve and list the top 30 incident's alerts. 
For each alert, retrieve its ID, name, tags, severity, investigation state, status, impacted assets, correlation reason, detection source, first activity, and last activity. Ensure that no duplicate IDs are in the list (if any, chose only the one with the last activity date).
Return this list as a table; include in the table all the retrieved columns but the ID column. List the incident by last activity date descending and add a number to each row, starting from 1.
If there are additional alerts beyond the first 30, clearly specify that there are more alerts in the incident just after the table and provide a link to the incident in the Defender portal.
Give the number of alerts exactly as the number of the last row in the table.

Then return a paragraph named "Incident Assets".
Retrieve and list the 'assets' involved in the incident, of type: 'devices', 'users', 'mailboxes', 'apps', and 'cloud resources'. 
Return their list by type. 
For each asset of type 'device', provide its name, domain, risk level, exposure level, and OS platform. 
For 'users', provide name (display name and UPN), user status, domain, and department. 
For 'apps', provide app name, app client ID, risk, and publisher. 
For 'cloud resources', provide Resource name, status, cloud environment, and type.
Count the total number of assets by type only once you have retrieved their lists (do not try to guess those numbers before getting the entire lists).

Then return a paragraph named "Incident Evidences".
Retrieve and list the 'evidences' involved in the incident - only those classified as malicious or suspicious - of type: 'processes', 'files', 'IP addresses', 'AD domains', and 'URLs'. 
For 'processes' get them all those classified as malicious or suspicious but return only the first 10 that, in your judgement, are the most probabile sign of malicious activity.
Do the same for 'files' get them all those classified as malicious or suspicious but return only the first 10 that, in your judgement, are the most probable sign of malicious activity.
For 'IP addresses', get them all those classified as malicious or suspicious, filter out those that are internal according o RFC1918 and, for the filtered list, return only the first 10.
For 'URLs', get them all those classified as malicious or suspicious, filter out those referring to a DNS domain associated to the existing tenant and return only the first 10.
For 'AD domains' return them all.
If there are additional evidences, beyond the first 10 of every type, clearly specify that there are more of these evidences in the incident just after the respective table and provide a link to the incident in the Defender portal.
Count the total number of evidences by type only once you have retrieved their list (do not try to guess that number before getting the entire list, capped to 10 by type). If there are additional evidences by type beyond the first 10, clearly specify that there are more evidences of that type in the incident and provide a link to the incident in the Defender portal.
