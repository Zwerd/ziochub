/* ----- Hunter's Playbook: OSINT & Threat Intel Sites (Tabs Layout) ----- */
(function () {
    "use strict";

    const playbookSitesBuiltIn = [
        {
            type: 'workflow',
            id: 'workflow',
            name: 'Workflow',
            content: `
<p><strong>Hunter's Playbook</strong> is your quick-reference guide for IOC research and threat intelligence. On this screen you have:</p>
<ul>
<li><strong>Left panel</strong> - Tabs for each recommended online tool or group of resources. Use the search box to filter by name, and the tag buttons to filter by type (e.g. IP, Hash, or <span class="playbook-tab-tag">Essential</span> for the most recommended tools 🔥).</li>
<li><strong>Right panel</strong> - For each tab you get a short description, practical examples, and tips so you know how to use the tool for IOC hunting.</li>
</ul>
<p>When you have submitted an IOC to ZIoCHub, use the workflow below as the next steps.</p>
<div class="playbook-divider"></div>
<h4 class="playbook-section-title">Recommended workflow after submitting an IOC</h4>
<div class="playbook-section-content">
<ol class="list-decimal pl-6 space-y-2">
<li><strong>Validate the indicator</strong> - Use VirusTotal or similar to confirm the IOC is malicious and see detection rates and related indicators.</li>
<li><strong>Enrich context</strong> - Search the same IOC in OTX, AbuseIPDB, or ThreatCrowd to find pulses, campaigns, and related infrastructure.</li>
<li><strong>Map to threats</strong> - Use MITRE ATT&CK or Malpedia to identify malware families and threat groups, and to pull IOCs from known campaigns.</li>
<li><strong>Document and share</strong> - Add comments and tags in ZIoCHub, link to tickets, and assign to campaigns so the team can reuse the context.</li>
</ol>
<p>Filter by <span class="playbook-tab-tag">Essential</span> to see only the most recommended tools (🔥) for day-to-day IOC hunting.</p>
</div>
`
        },
        {
            id: 'virustotal',
            name: 'VirusTotal',
            url: 'https://www.virustotal.com',
            isEssential: true,
            tags: ['IP', 'Domain', 'Hash', 'URL', 'Email'],
            description: 'VirusTotal is a critical multi-engine antivirus scanner and threat intelligence platform. It aggregates results from 70+ antivirus engines, URL scanners, and domain reputation services. Essential for quick IOC validation, finding related indicators, and understanding detection rates across vendors.',
            examples: `
<p><strong>Example 1: Searching for an IP address</strong></p>
<p>When investigating a suspicious IP (e.g., <code>185.220.101.42</code>), paste it into VirusTotal's search. You'll see:</p>
<ul>
<li>Detection count and vendor names</li>
<li>Related URLs, domains, and file hashes</li>
<li>Community comments and tags</li>
<li>Passive DNS records and WHOIS</li>
</ul>
<p>Use the "Relations" tab to discover connected indicators - often reveals C2 infrastructure or malware distribution networks.</p>
<p><strong>Example 2: Domain research</strong></p>
<p>Search a domain (e.g., <code>malicious-example.com</code>) to find:</p>
<ul>
<li>Subdomains and related domains</li>
<li>Files downloaded from this domain</li>
<li>IP addresses it resolves to</li>
<li>Historical DNS changes</li>
</ul>
<p>This helps map the full attack infrastructure and identify other compromised domains.</p>
<p><strong>Example 3: Hash lookup for malware attribution</strong></p>
<p>Submit a file hash (MD5, SHA256) to see:</p>
<ul>
<li>Detection names from multiple AV engines</li>
<li>Behavioral analysis and sandbox reports</li>
<li>Related samples and variants</li>
<li>MITRE ATT&CK techniques mapped</li>
</ul>
<p>Correlate detection names (e.g., "Trojan.Win32.Emotet") with threat intelligence to identify the malware family and campaign.</p>
`,
            tips: `
<p><strong>IOC Search Tips:</strong></p>
<ul>
<li><strong>IP:</strong> Direct search - use Relations tab to find domains, URLs, and files</li>
<li><strong>Domain:</strong> Search domain name - check Subdomains and Passive DNS tabs</li>
<li><strong>URL:</strong> Paste full URL - see detection rate and related files</li>
<li><strong>Hash:</strong> Search MD5/SHA1/SHA256 - view behavioral analysis and related samples</li>
<li><strong>Email:</strong> Search email address - find associated domains and files</li>
</ul>
<p><strong>Pro Tips:</strong></p>
<ul>
<li>Use the API (requires free API key) to automate IOC lookups in your workflow</li>
<li>Check "Community" tab for analyst notes and attribution hints</li>
<li>Export related IOCs as CSV for bulk import into ZIoCHub</li>
<li>Set up VT Intelligence queries for ongoing monitoring of specific indicators</li>
</ul>
`
        },
        {
            id: 'otx',
            name: 'AlienVault OTX',
            url: 'https://otx.alienvault.com',
            isEssential: true,
            tags: ['IP', 'Domain', 'Hash', 'Email', 'Campaign'],
            description: 'AlienVault OTX (Open Threat Exchange) is a collaborative threat intelligence platform where security researchers share indicators, pulses (threat reports), and adversary context. It provides community-driven IOC feeds, malware family information, and attribution data. Critical for understanding threat campaigns and finding related indicators from the security community.',
            examples: `
<p><strong>Example 1: Finding related IOCs from a campaign</strong></p>
<p>Search for a known indicator (e.g., IP <code>192.0.2.1</code>) and view its "Pulses" - these are threat reports that include this IOC. Each pulse contains:</p>
<ul>
<li>Related IPs, domains, URLs, and hashes</li>
<li>Malware family and campaign name</li>
<li>Adversary attribution (if known)</li>
<li>MITRE ATT&CK techniques</li>
</ul>
<p>Export all IOCs from a pulse to enrich your investigation with community findings.</p>
<p><strong>Example 2: Researching a malware family</strong></p>
<p>Search for a malware name (e.g., "Emotet", "TrickBot") to find pulses describing campaigns, IOCs, and TTPs. Use this to:</p>
<ul>
<li>Identify other indicators from the same campaign</li>
<li>Understand the attack chain and techniques</li>
<li>Find attribution to threat groups</li>
</ul>
<p><strong>Example 3: Subscribing to threat feeds</strong></p>
<p>Browse "Pulses" by category (Malware, Phishing, etc.) and subscribe to feeds from trusted sources. OTX will notify you when new IOCs matching your interests are published.</p>
`,
            tips: `
<p><strong>IOC Search Tips:</strong></p>
<ul>
<li><strong>IP:</strong> Search IP - view all pulses containing this IP and related indicators</li>
<li><strong>Domain:</strong> Search domain - see pulses and related domains/IPs</li>
<li><strong>Hash:</strong> Search file hash - find pulses describing the malware</li>
<li><strong>Email:</strong> Search email - find phishing campaigns and related domains</li>
</ul>
<p><strong>Pro Tips:</strong></p>
<ul>
<li>Create an OTX account (free) to subscribe to feeds and create custom pulse collections</li>
<li>Use OTX API to integrate IOC lookups into your automation</li>
<li>Follow trusted contributors (e.g., abuse.ch, security vendors) for high-quality pulses</li>
<li>Export pulses as STIX/TAXII for integration with SIEM platforms</li>
</ul>
`
        },
        {
            id: 'abuseipdb',
            name: 'AbuseIPDB',
            url: 'https://www.abuseipdb.com',
            isEssential: true,
            tags: ['IP'],
            description: 'AbuseIPDB is a reputation database for IP addresses, focusing on abuse reports from the community. It tracks IPs reported for spam, brute force, malware distribution, and other malicious activities. Essential for quick IP reputation checks and understanding why an IP might be flagged.',
            examples: `
<p><strong>Example 1: Checking IP reputation</strong></p>
<p>Search an IP address (e.g., <code>203.0.113.1</code>) to see:</p>
<ul>
<li>Abuse confidence percentage (0-100%)</li>
<li>Number of reports and categories (spam, malware, etc.)</li>
<li>Geolocation and ISP information</li>
<li>Usage type (hosting, data center, etc.)</li>
</ul>
<p>High confidence scores (>75%) indicate likely malicious activity - prioritize these for blocking.</p>
<p><strong>Example 2: Understanding abuse categories</strong></p>
<p>Each report includes a category (e.g., "Brute-Force", "Malware", "Spam"). Review recent reports to understand:</p>
<ul>
<li>What type of attack this IP is associated with</li>
<li>When the abuse was first reported</li>
<li>If the IP is still active</li>
</ul>
<p><strong>Example 3: Bulk IP checking</strong></p>
<p>Use the API (free tier available) to check multiple IPs programmatically. Useful for validating IPs before adding them to ZIoCHub.</p>
`,
            tips: `
<p><strong>IOC Search Tips:</strong></p>
<ul>
<li><strong>IP:</strong> Direct search - view reputation score, reports, and geolocation</li>
<li><strong>Domain:</strong> Not directly supported - resolve domain to IP first, then check IP</li>
</ul>
<p><strong>Pro Tips:</strong></p>
<ul>
<li>Register for free API access (1000 requests/day) to automate IP checks</li>
<li>Use the "Check Block" feature to see if an IP is in common blocklists</li>
<li>Contribute reports when you encounter malicious IPs - helps the community</li>
<li>Check "Usage Type" - data center IPs are often proxies/VPNs, which may be legitimate</li>
</ul>
`
        },
        {
            id: 'threatcrowd',
            name: 'ThreatCrowd',
            url: 'https://threatcrowd.org',
            tags: ['IP', 'Domain', 'Hash', 'Email'],
            description: 'ThreatCrowd is a search engine for threat intelligence that visualizes relationships between indicators. It creates graphs showing how IPs, domains, emails, and hashes are connected. Critical for mapping attack infrastructure and discovering related indicators through relationship analysis.',
            examples: `
<p><strong>Example 1: Visualizing indicator relationships</strong></p>
<p>Search an IP address to see an interactive graph showing:</p>
<ul>
<li>Domains that resolve to this IP</li>
<li>Other IPs in the same subnet</li>
<li>Related email addresses</li>
<li>Files (hashes) associated with this IP</li>
</ul>
<p>Click any node in the graph to expand and discover more connections - reveals full attack infrastructure.</p>
<p><strong>Example 2: Domain relationship mapping</strong></p>
<p>Search a domain to find:</p>
<ul>
<li>IP addresses it resolves to</li>
<li>Related domains (often from same registrar or hosting)</li>
<li>Email addresses associated with the domain</li>
<li>Subdomains</li>
</ul>
<p>Use this to identify other domains in the same campaign or infrastructure.</p>
<p><strong>Example 3: Email investigation</strong></p>
<p>Search an email address to find:</p>
<ul>
<li>Domains associated with this email</li>
<li>IPs and other emails in the same network</li>
<li>Files uploaded by this email</li>
</ul>
<p>Helps identify phishing campaigns and related infrastructure.</p>
`,
            tips: `
<p><strong>IOC Search Tips:</strong></p>
<ul>
<li><strong>IP:</strong> Search IP - view relationship graph and expand nodes</li>
<li><strong>Domain:</strong> Search domain - see related domains, IPs, and emails</li>
<li><strong>Email:</strong> Search email - find associated domains and infrastructure</li>
<li><strong>Hash:</strong> Search MD5/SHA256 - see related IPs, domains, and other samples</li>
</ul>
<p><strong>Pro Tips:</strong></p>
<ul>
<li>Use the graph visualization to understand attack infrastructure - click nodes to expand</li>
<li>Export graph data as JSON for further analysis</li>
<li>Combine with VirusTotal for deeper IOC validation</li>
<li>Check "Passive DNS" tab for historical domain-to-IP mappings</li>
</ul>
`
        },
        {
            id: 'urlhaus',
            name: 'URLhaus',
            url: 'https://urlhaus.abuse.ch',
            tags: ['URL', 'Domain', 'IP', 'Hash'],
            description: 'URLhaus is a project by abuse.ch that tracks malware distribution URLs. It provides a database of malicious URLs, associated file hashes, and hosting information. Critical for identifying malware distribution infrastructure and finding related samples.',
            examples: `
<p><strong>Example 1: Checking a suspicious URL</strong></p>
<p>Paste a URL (e.g., <code>http://malicious-example.com/payload.exe</code>) to see:</p>
<ul>
<li>If the URL is known to distribute malware</li>
<li>Associated file hashes (MD5, SHA256)</li>
<li>Hosting IP and ASN information</li>
<li>First and last seen dates</li>
</ul>
<p>If the URL is flagged, download the associated hash and search it in VirusTotal for malware analysis.</p>
<p><strong>Example 2: Finding malware distribution infrastructure</strong></p>
<p>Search by hosting IP to find all malicious URLs hosted on that IP. This reveals:</p>
<ul>
<li>Other malware distribution URLs</li>
<li>Patterns in URL structure</li>
<li>Campaign infrastructure</li>
</ul>
<p><strong>Example 3: Hash lookup</strong></p>
<p>Search a file hash to find URLs that distributed this malware sample. Use this to identify other distribution points and related infrastructure.</p>
`,
            tips: `
<p><strong>IOC Search Tips:</strong></p>
<ul>
<li><strong>URL:</strong> Paste full URL - see if it's flagged and get associated hashes</li>
<li><strong>Domain:</strong> Search domain - find all malicious URLs on this domain</li>
<li><strong>IP:</strong> Search hosting IP - discover all malware URLs hosted on this IP</li>
<li><strong>Hash:</strong> Search MD5/SHA256 - find URLs that distributed this malware</li>
</ul>
<p><strong>Pro Tips:</strong></p>
<ul>
<li>Use URLhaus API for automated URL checks</li>
<li>Subscribe to URLhaus feeds for ongoing monitoring</li>
<li>Check "Tags" to understand malware families (e.g., "Emotet", "TrickBot")</li>
<li>Export IOCs as CSV for bulk import into ZIoCHub</li>
</ul>
`
        },
        {
            id: 'malwarebazaar',
            name: 'MalwareBazaar',
            url: 'https://bazaar.abuse.ch',
            tags: ['Hash', 'YARA', 'Malware'],
            description: 'MalwareBazaar is a malware sample database by abuse.ch that provides access to malware samples, YARA rules, and related intelligence. Analysts can download samples, view YARA rules, and find related indicators. Critical for malware analysis, YARA rule development, and understanding malware families.',
            examples: `
<p><strong>Example 1: Searching for malware samples</strong></p>
<p>Search by hash (MD5, SHA256) or malware family name (e.g., "Emotet") to find:</p>
<ul>
<li>Malware samples available for download</li>
<li>YARA rules that detect this malware</li>
<li>Related samples and variants</li>
<li>Tags and classification</li>
</ul>
<p>Download samples for analysis or use YARA rules in your detection systems.</p>
<p><strong>Example 2: Finding YARA rules</strong></p>
<p>Browse YARA rules by malware family or download rules for specific samples. Each rule includes:</p>
<ul>
<li>Rule name and description</li>
<li>Strings and conditions</li>
<li>Malware family detection</li>
</ul>
<p>Use these rules as templates or import directly into your YARA rule repository.</p>
<p><strong>Example 3: Submitting samples</strong></p>
<p>Upload malware samples to contribute to the community. MalwareBazaar will:</p>
<ul>
<li>Generate YARA rules automatically</li>
<li>Share samples with the security community</li>
<li>Provide download links for analysis</li>
</ul>
`,
            tips: `
<p><strong>IOC Search Tips:</strong></p>
<ul>
<li><strong>Hash:</strong> Search MD5/SHA256 - find sample, YARA rules, and related samples</li>
<li><strong>Malware Family:</strong> Search family name - browse all samples and YARA rules</li>
<li><strong>Tag:</strong> Browse by tag (e.g., "banker", "trojan") - find related samples</li>
</ul>
<p><strong>Pro Tips:</strong></p>
<ul>
<li>Use MalwareBazaar API to automate hash lookups and YARA rule downloads</li>
<li>Download YARA rules and adapt them for your environment</li>
<li>Check "Related Samples" to find variants and related malware</li>
<li>Subscribe to RSS feeds for new samples in specific malware families</li>
</ul>
<p><strong>YARA Tips:</strong></p>
<ul>
<li>Download YARA rules from MalwareBazaar and review their structure</li>
<li>Use these rules as templates for creating your own detection rules</li>
<li>Test rules against your sample set before deploying to production</li>
</ul>
`
        },
        {
            id: 'hybrid-analysis',
            name: 'Hybrid Analysis',
            url: 'https://www.hybrid-analysis.com',
            isEssential: true,
            tags: ['Hash', 'IP', 'Domain', 'Sandbox'],
            description: 'Hybrid Analysis is a free automated malware analysis sandbox. It executes files in a controlled environment and provides detailed behavioral reports, network activity, and threat intelligence. Critical for understanding malware behavior, C2 communication, and extracting IOCs from samples.',
            examples: `
<p><strong>Example 1: Analyzing a suspicious file</strong></p>
<p>Upload a file (or search by hash) to get a comprehensive analysis report including:</p>
<ul>
<li>Behavioral analysis (file system, registry, network activity)</li>
<li>Network connections and C2 IPs/domains</li>
<li>Dropped files and their hashes</li>
<li>MITRE ATT&CK techniques mapped</li>
<li>Threat score and verdict</li>
</ul>
<p>Extract all IOCs (IPs, domains, URLs, hashes) from the report and add them to ZIoCHub.</p>
<p><strong>Example 2: Searching by IOC</strong></p>
<p>Search an IP address or domain to find:</p>
<ul>
<li>All samples that contacted this IP/domain</li>
<li>Malware families associated with this C2</li>
<li>Related samples and campaigns</li>
</ul>
<p>Use this to identify other malware samples in the same campaign.</p>
<p><strong>Example 3: Comparing samples</strong></p>
<p>Compare multiple samples to identify similarities in behavior, C2 infrastructure, and techniques. Helps attribute samples to the same threat actor or campaign.</p>
`,
            tips: `
<p><strong>IOC Search Tips:</strong></p>
<ul>
<li><strong>Hash:</strong> Search MD5/SHA256 - view full analysis report and extract IOCs</li>
<li><strong>IP:</strong> Search IP - find all samples that contacted this IP</li>
<li><strong>Domain:</strong> Search domain - discover malware samples using this C2</li>
<li><strong>URL:</strong> Search URL - find samples that downloaded from this URL</li>
</ul>
<p><strong>Pro Tips:</strong></p>
<ul>
<li>Create a free account to access full reports and download PCAPs</li>
<li>Use the API to automate file submissions and IOC extraction</li>
<li>Export IOCs as CSV or STIX for import into ZIoCHub</li>
<li>Check "Threat Indicators" section for C2 IPs, domains, and URLs</li>
<li>Review "MITRE ATT&CK" mapping to understand attack techniques</li>
</ul>
`
        },
        {
            id: 'malpedia',
            name: 'Malpedia',
            url: 'https://malpedia.caad.fkie.fraunhofer.de',
            tags: ['Malware', 'APT', 'YARA', 'Campaign'],
            description: 'Malpedia is a comprehensive malware encyclopedia that provides detailed information about malware families, APT groups, and their associated IOCs. It includes YARA rules, behavioral descriptions, and attribution data. Critical for malware family identification, threat attribution, and YARA rule development.',
            examples: `
<p><strong>Example 1: Identifying malware families</strong></p>
<p>Search a malware name (e.g., "Emotet", "TrickBot") to find:</p>
<ul>
<li>Detailed family description and behavior</li>
<li>Associated APT groups and campaigns</li>
<li>YARA rules for detection</li>
<li>Related IOCs (IPs, domains, hashes)</li>
<li>MITRE ATT&CK techniques</li>
</ul>
<p>Use this to understand the threat and find related indicators.</p>
<p><strong>Example 2: APT group research</strong></p>
<p>Search an APT group name (e.g., "APT28", "Lazarus") to see:</p>
<ul>
<li>All malware families used by this group</li>
<li>Known campaigns and IOCs</li>
<li>Attribution and aliases</li>
<li>YARA rules for their malware</li>
</ul>
<p><strong>Example 3: YARA rule development</strong></p>
<p>Browse YARA rules by malware family to:</p>
<ul>
<li>See how other analysts detect this malware</li>
<li>Use rules as templates for your own</li>
<li>Understand detection patterns</li>
</ul>
`,
            tips: `
<p><strong>IOC Search Tips:</strong></p>
<ul>
<li><strong>Malware Family:</strong> Search family name - view IOCs, YARA rules, and attribution</li>
<li><strong>APT Group:</strong> Search group name - find all associated malware and IOCs</li>
<li><strong>Hash:</strong> Search hash - identify malware family if sample is known</li>
</ul>
<p><strong>Pro Tips:</strong></p>
<ul>
<li>Download YARA rules and adapt them for your environment</li>
<li>Use Malpedia to map IOCs to threat actors and campaigns</li>
<li>Check "References" for detailed analysis reports</li>
<li>Export IOCs as JSON/CSV for import into ZIoCHub</li>
</ul>
<p><strong>YARA Tips:</strong></p>
<ul>
<li>Malpedia provides high-quality YARA rules - use them as templates</li>
<li>Review rule structure to understand detection patterns</li>
<li>Test rules against your sample set before deploying</li>
<li>Combine multiple rules for better coverage</li>
</ul>
`
        },
        {
            id: 'mandiant',
            name: 'Mandiant Threat Intelligence',
            url: 'https://www.mandiant.com',
            tags: ['APT', 'Campaign', 'Threat Group'],
            description: 'Mandiant (now part of Google Cloud) provides threat intelligence reports, APT group profiles, and attribution analysis. Their research covers nation-state actors, cybercrime groups, and major campaigns. Critical for understanding threat actor TTPs, attribution, and finding related IOCs from published research.',
            examples: `
<p><strong>Example 1: APT group research</strong></p>
<p>Search for APT group names (e.g., "UNC3000", "APT1") to find:</p>
<ul>
<li>Detailed group profiles and capabilities</li>
<li>Known campaigns and IOCs</li>
<li>Attribution and geopolitical context</li>
<li>TTPs and attack chains</li>
</ul>
<p>Use this to understand threat actors and identify related infrastructure.</p>
<p><strong>Example 2: Campaign analysis</strong></p>
<p>Browse threat intelligence reports to find:</p>
<ul>
<li>Recent campaigns and their IOCs</li>
<li>Attack techniques and tools</li>
<li>Infrastructure mapping</li>
<li>Attribution details</li>
</ul>
<p><strong>Example 3: IOC enrichment</strong></p>
<p>When you have IOCs from an attack, search Mandiant reports to see if they match known campaigns or groups. This helps with attribution and finding related indicators.</p>
`,
            tips: `
<p><strong>IOC Search Tips:</strong></p>
<ul>
<li><strong>APT Group:</strong> Search group name - view reports, campaigns, and IOCs</li>
<li><strong>Campaign:</strong> Search campaign name - find all associated IOCs</li>
<li><strong>Malware:</strong> Search malware name - find groups using it and related campaigns</li>
</ul>
<p><strong>Pro Tips:</strong></p>
<ul>
<li>Subscribe to Mandiant threat intelligence feeds for ongoing updates</li>
<li>Use their API (if available) to automate IOC lookups</li>
<li>Check "Threat Intelligence" section for latest research</li>
<li>Export IOCs from reports for import into ZIoCHub</li>
</ul>
`
        },
        {
            id: 'securitytrails',
            name: 'SecurityTrails',
            url: 'https://securitytrails.com',
            tags: ['Domain', 'IP', 'DNS'],
            description: 'SecurityTrails provides comprehensive DNS history, subdomain enumeration, and infrastructure intelligence. It tracks historical DNS records, IP changes, and domain relationships. Critical for mapping attack infrastructure, finding related domains, and understanding domain evolution over time.',
            examples: `
<p><strong>Example 1: Domain history research</strong></p>
<p>Search a domain to see:</p>
<ul>
<li>Historical DNS records (A, AAAA, MX, NS)</li>
<li>IP address changes over time</li>
<li>Subdomains and related domains</li>
<li>WHOIS history and registrar changes</li>
</ul>
<p>Use this to identify when a domain was created, when it changed IPs, and find other domains in the same infrastructure.</p>
<p><strong>Example 2: Finding related infrastructure</strong></p>
<p>Search by IP address to find:</p>
<ul>
<li>All domains that currently resolve to this IP</li>
<li>Historical domains that used this IP</li>
<li>Subdomains and related infrastructure</li>
</ul>
<p>Helps map the full attack infrastructure and identify other compromised domains.</p>
<p><strong>Example 3: Subdomain enumeration</strong></p>
<p>Use SecurityTrails to discover subdomains of a target domain. This reveals:</p>
<ul>
<li>Hidden or forgotten subdomains</li>
<li>Development and staging environments</li>
<li>Potential attack vectors</li>
</ul>
`,
            tips: `
<p><strong>IOC Search Tips:</strong></p>
<ul>
<li><strong>Domain:</strong> Search domain - view DNS history, subdomains, and IP changes</li>
<li><strong>IP:</strong> Search IP - find all domains that resolve/resolved to this IP</li>
<li><strong>Subdomain:</strong> Search subdomain - see parent domain and related infrastructure</li>
</ul>
<p><strong>Pro Tips:</strong></p>
<ul>
<li>Create a free account for basic searches (limited results)</li>
<li>Use SecurityTrails API to automate DNS lookups</li>
<li>Check "Historical Data" to see domain evolution</li>
<li>Export subdomain lists as CSV for further analysis</li>
<li>Combine with VirusTotal for comprehensive domain research</li>
</ul>
`
        },
        {
            id: 'apt-intel-dashboard',
            name: 'APT Intelligence Dashboard',
            url: 'https://michaelelizarov.github.io/apt-intelligence-dashboard/',
            isEssential: true,
            tags: ['APT', 'Threat Group', 'Campaign', 'Dashboard'],
            description: 'APT Intelligence Dashboard is a comprehensive open-source dashboard that aggregates APT group intelligence from multiple sources. It provides a unified view of threat actors, their campaigns, IOCs, and TTPs. Critical for quick APT group research and finding related indicators across different intelligence sources.',
            examples: `
<p><strong>Example 1: Researching an APT group</strong></p>
<p>Search for an APT group name (e.g., "APT28", "Lazarus") to see:</p>
<ul>
<li>Group aliases and attribution</li>
<li>Known campaigns and IOCs</li>
<li>Associated malware families</li>
<li>MITRE ATT&CK techniques</li>
<li>Links to detailed reports</li>
</ul>
<p>Use this dashboard to quickly get an overview of a threat group and find related indicators.</p>
<p><strong>Example 2: Campaign analysis</strong></p>
<p>Browse campaigns to find:</p>
<ul>
<li>All IOCs associated with a campaign</li>
<li>Threat groups behind the campaign</li>
<li>Timeline and attribution</li>
<li>Related infrastructure</li>
</ul>
<p><strong>Example 3: IOC enrichment</strong></p>
<p>When you have IOCs from an attack, use the dashboard to see if they match known APT campaigns or groups. This helps with attribution and finding related indicators.</p>
`,
            tips: `
<p><strong>IOC Search Tips:</strong></p>
<ul>
<li><strong>APT Group:</strong> Search group name - view campaigns, IOCs, and attribution</li>
<li><strong>Campaign:</strong> Browse campaigns - find all associated IOCs and groups</li>
<li><strong>Malware:</strong> Search malware name - find APT groups using it</li>
</ul>
<p><strong>Pro Tips:</strong></p>
<ul>
<li>Use the dashboard as a starting point for APT research</li>
<li>Follow links to detailed reports for deeper analysis</li>
<li>Export IOCs from campaigns for import into ZIoCHub</li>
<li>Check the timeline to understand campaign evolution</li>
</ul>
`
        },
        {
            id: 'mitre-attack',
            name: 'MITRE ATT&CK',
            url: 'https://attack.mitre.org',
            isEssential: true,
            tags: ['Campaign', 'Threat Group', 'TTP'],
            description: 'MITRE ATT&CK is a knowledge base of adversary tactics and techniques based on real-world observations. It maps threat actor groups, malware families, and campaigns to specific techniques. Critical for threat attribution, understanding attack chains, and mapping IOCs to threat actors.',
            examples: `
<p><strong>Example 1: Mapping IOCs to threat groups</strong></p>
<p>When you have IOCs from an attack, search MITRE ATT&CK for:</p>
<ul>
<li>Threat groups (e.g., "APT28", "Lazarus") that use similar techniques</li>
<li>Malware families associated with these groups</li>
<li>Campaigns and known IOCs</li>
</ul>
<p>Compare your IOCs with known group infrastructure to identify attribution.</p>
<p><strong>Example 2: Understanding attack techniques</strong></p>
<p>If you observe specific behaviors (e.g., "PowerShell execution", "Lateral movement"), search MITRE ATT&CK to:</p>
<ul>
<li>Find techniques (e.g., T1059.001, T1021)</li>
<li>See which threat groups use these techniques</li>
<li>Understand the full attack chain</li>
</ul>
<p><strong>Example 3: Researching a threat group</strong></p>
<p>Search for a threat group name to see:</p>
<ul>
<li>All techniques they use</li>
<li>Associated malware families</li>
<li>Known campaigns and IOCs</li>
<li>Attribution and aliases</li>
</ul>
<p>Use this to understand their TTPs and identify other indicators they might use.</p>
`,
            tips: `
<p><strong>IOC Search Tips:</strong></p>
<ul>
<li><strong>Threat Group:</strong> Search group name - view techniques, malware, and campaigns</li>
<li><strong>Malware Family:</strong> Search malware name - find associated groups and techniques</li>
<li><strong>Technique:</strong> Search technique ID (e.g., "T1059") - see which groups use it</li>
</ul>
<p><strong>Pro Tips:</strong></p>
<ul>
<li>Use ATT&CK Navigator to visualize group techniques and compare groups</li>
<li>Export group data as JSON/STIX for integration with SIEM</li>
<li>Check "Software" section to find malware families and their associated groups</li>
<li>Use ATT&CK API to programmatically query techniques and groups</li>
</ul>
<p><strong>YARA Tips:</strong></p>
<ul>
<li>While MITRE ATT&CK doesn't provide YARA rules directly, use it to understand which techniques to detect</li>
<li>Map your YARA rules to ATT&CK techniques for better threat intelligence</li>
<li>Use ATT&CK to identify which malware families your rules should cover</li>
</ul>
`
        },
        {
            id: 'shodan',
            name: 'Shodan',
            url: 'https://www.shodan.io',
            tags: ['IP', 'Network'],
            description: 'Shodan is a search engine for internet-connected devices. It indexes services, ports, and banners exposed on the internet. Critical for understanding what services an IP is running, identifying exposed infrastructure, and finding vulnerable devices that might be part of an attack infrastructure.',
            examples: `
<p><strong>Example 1: Investigating an IP address</strong></p>
<p>Search an IP to see:</p>
<ul>
<li>Open ports and services</li>
<li>Banner information and service versions</li>
<li>Geolocation and ISP</li>
<li>Hosting information (data center, cloud provider)</li>
</ul>
<p>Use this to understand if an IP is hosting malicious services or is part of infrastructure.</p>
<p><strong>Example 2: Finding exposed services</strong></p>
<p>Use Shodan filters to find:</p>
<ul>
<li>IPs running specific services (e.g., "port:3389" for RDP)</li>
<li>Vulnerable software versions</li>
<li>Exposed databases or web servers</li>
</ul>
<p>Helps identify potential attack vectors and compromised infrastructure.</p>
<p><strong>Example 3: Infrastructure mapping</strong></p>
<p>Search by organization or ASN to map all internet-facing infrastructure. Use this to:</p>
<ul>
<li>Identify all public IPs belonging to an organization</li>
<li>Find exposed services and potential vulnerabilities</li>
<li>Understand attack surface</li>
</ul>
`,
            tips: `
<p><strong>IOC Search Tips:</strong></p>
<ul>
<li><strong>IP:</strong> Search IP - view ports, services, and banners</li>
<li><strong>Domain:</strong> Resolve domain to IP first, then search IP in Shodan</li>
<li><strong>Port/Service:</strong> Use filters (e.g., "port:443", "product:Apache") - find IPs running specific services</li>
</ul>
<p><strong>Pro Tips:</strong></p>
<ul>
<li>Create a free Shodan account for basic searches (limited results)</li>
<li>Use Shodan API to automate IP lookups and service discovery</li>
<li>Check "Vulnerabilities" tab to see if IP has known CVEs</li>
<li>Use filters like "org:", "asn:", "country:" to narrow searches</li>
<li>Export results as JSON/CSV for further analysis</li>
</ul>
`
        },
        {
            id: 'anyrun',
            name: 'Any.Run',
            url: 'https://any.run',
            tags: ['Hash', 'URL', 'Sandbox', 'IP', 'Domain'],
            description: 'Any.Run is an interactive malware analysis sandbox that provides real-time behavioral analysis. It allows analysts to interact with malware samples in a controlled environment, making it ideal for understanding C2 communication, user interaction, and dynamic behavior. Critical for deep malware analysis and extracting IOCs from interactive samples.',
            examples: `
<p><strong>Example 1: Interactive malware analysis</strong></p>
<p>Upload a file or submit a URL to get an interactive analysis session where you can:</p>
<ul>
<li>Watch malware execute in real-time</li>
<li>Interact with the sample (click buttons, enter data)</li>
<li>See network connections as they happen</li>
<li>Observe file system and registry changes</li>
<li>Extract C2 IPs, domains, and URLs</li>
</ul>
<p>Use the interactive interface to trigger different behaviors and extract more IOCs.</p>
<p><strong>Example 2: URL analysis</strong></p>
<p>Submit a suspicious URL to see:</p>
<ul>
<li>What files are downloaded</li>
<li>Network connections made</li>
<li>Behavioral indicators</li>
<li>Threat score and verdict</li>
</ul>
<p><strong>Example 3: Searching by IOC</strong></p>
<p>Search an IP or domain to find all samples that contacted it. This reveals:</p>
<ul>
<li>Malware families using this C2</li>
<li>Related samples and campaigns</li>
<li>Attack patterns and techniques</li>
</ul>
`,
            tips: `
<p><strong>IOC Search Tips:</strong></p>
<ul>
<li><strong>IP:</strong> Search IP - find all samples that contacted this IP</li>
<li><strong>Domain:</strong> Search domain - discover malware using this C2</li>
<li><strong>URL:</strong> Submit URL - analyze what it downloads and connects to</li>
<li><strong>Hash:</strong> Search MD5/SHA256 - view interactive analysis if available</li>
</ul>
<p><strong>Pro Tips:</strong></p>
<ul>
<li>Create a free account for basic analysis (limited submissions)</li>
<li>Use the interactive interface to understand malware behavior step-by-step</li>
<li>Export network traffic (PCAP) for deeper analysis</li>
<li>Check "Threat Intelligence" tab for related IOCs and attribution</li>
<li>Use tags and verdicts to prioritize threats</li>
</ul>
`
        },
        {
            type: 'group',
            id: 'cyber-news',
            name: 'Cyber Security News',
            tags: ['News', 'Reading'],
            sites: [
                {
                    name: 'Krebs on Security',
                    url: 'https://krebsonsecurity.com',
                    description: 'Brian Krebs\' investigative cybersecurity blog covering data breaches, cybercrime, and threat actor activities. Essential for staying updated on major incidents and threat intelligence.'
                },
                {
                    name: 'BleepingComputer',
                    url: 'https://www.bleepingcomputer.com',
                    description: 'Cybersecurity news site covering malware, vulnerabilities, and security incidents. Provides detailed analysis and IOCs from recent attacks.'
                },
                {
                    name: 'The Record',
                    url: 'https://therecord.media',
                    description: 'Cybersecurity news publication covering threat intelligence, data breaches, and nation-state attacks. Often includes IOCs and attribution details.'
                },
                {
                    name: 'Dark Reading',
                    url: 'https://www.darkreading.com',
                    description: 'Information security news and analysis covering threats, vulnerabilities, and security strategies. Useful for understanding attack trends.'
                },
                {
                    name: 'Feedly',
                    url: 'https://feedly.com',
                    description: 'RSS feed aggregator and news reader. Essential for consolidating cybersecurity news feeds from multiple sources (Krebs, BleepingComputer, vendor blogs) into a single dashboard. Helps analysts stay updated on threat intelligence and IOCs from various sources.'
                }
            ]
        },
        {
            type: 'group',
            id: 'vulnerabilities',
            name: 'Vulnerability Databases',
            tags: ['Vuln', 'CVE'],
            sites: [
                {
                    name: 'CVE Details',
                    url: 'https://www.cvedetails.com',
                    description: 'Comprehensive CVE database with search, filtering, and vulnerability statistics. Essential for researching CVEs, understanding severity, and finding affected products.'
                },
                {
                    name: 'National Vulnerability Database (NVD)',
                    url: 'https://nvd.nist.gov',
                    description: 'U.S. government repository of vulnerability data. Provides CVSS scores, CPE mappings, and detailed vulnerability information. Critical for vulnerability assessment.'
                },
                {
                    name: 'Exploit-DB',
                    url: 'https://www.exploit-db.com',
                    description: 'Database of exploits and proof-of-concept code. Useful for understanding how vulnerabilities are exploited and testing defenses.'
                }
            ]
        },
        {
            type: 'group',
            id: 'threat-intel',
            name: 'Threat Intelligence Reports',
            tags: ['Threat Intel', 'Reports'],
            sites: [
                {
                    name: 'Kaspersky Threat Intelligence',
                    url: 'https://securelist.com',
                    description: 'Kaspersky\'s threat intelligence blog covering APT groups, malware campaigns, and attribution. Provides detailed analysis reports with IOCs and TTPs.'
                },
                {
                    name: 'CrowdStrike Intelligence',
                    url: 'https://www.crowdstrike.com/blog',
                    description: 'Threat intelligence reports from CrowdStrike covering nation-state actors, cybercrime groups, and major campaigns. Includes IOCs and attribution details.'
                },
                {
                    name: 'FireEye (Mandiant) Threat Research',
                    url: 'https://www.mandiant.com/resources',
                    description: 'Threat research reports and APT group profiles from Mandiant. Covers attribution, TTPs, and campaign analysis with IOCs.'
                },
                {
                    name: 'Palo Alto Unit 42',
                    url: 'https://unit42.paloaltonetworks.com',
                    description: 'Threat intelligence research from Palo Alto Networks covering APT groups, malware families, and campaigns. Includes detailed IOCs and analysis.'
                }
            ]
        },
        {
            type: 'group',
            id: 'sandbox',
            name: 'Additional Sandbox Tools',
            tags: ['Sandbox', 'Analysis'],
            sites: [
                {
                    name: 'Joe Sandbox',
                    url: 'https://www.joesandbox.com',
                    description: 'Automated malware analysis sandbox with detailed behavioral reports. Provides network activity, file system changes, and IOC extraction.'
                },
                {
                    name: 'Cape Sandbox',
                    url: 'https://capesandbox.com',
                    description: 'Open-source automated malware analysis framework. Can be self-hosted for private analysis and IOC extraction.'
                },
                {
                    name: 'VMRay Analyzer',
                    url: 'https://www.vmray.com',
                    description: 'Advanced malware analysis platform with deep behavioral analysis. Provides detailed IOC reports and threat intelligence.'
                }
            ]
        },
        {
            type: 'group',
            id: 'yara-validation',
            name: 'YARA Validation',
            tags: ['YARA'],
            sites: [
                {
                    name: 'YARA Playground',
                    url: 'https://yaraplayground.com',
                    description: 'Free browser-based YARA validator and testing tool. Paste your rule and get real-time syntax errors and line numbers. You can also upload a sample file (up to 10 MB) to test if the rule matches. Runs entirely in the browser (WebAssembly) so rules and samples never leave your device. Essential for checking YARA syntax before uploading to ZIoCHub.'
                },
                {
                    name: 'YARA Documentation (Syntax)',
                    url: 'https://yara.readthedocs.io',
                    description: 'Official YARA documentation: language syntax, modules, and rule structure. Use this to verify correct keywords, string modifiers, condition syntax, and meta sections. Helpful when the validator reports an error and you need to fix the rule.'
                },
                {
                    name: 'YARA Rules (VirusTotal GitHub)',
                    url: 'https://github.com/VirusTotal/yara',
                    description: 'Official YARA project and grammar reference. The repository contains the language specification and grammar.y; useful for understanding valid syntax and for advanced rule writing. Combine with a validator to ensure rules compile correctly.'
                }
            ]
        }
    ];

    let playbookCustomFromApi = [];
    let playbookSites = playbookCustomFromApi.concat(playbookSitesBuiltIn);

    function loadPlaybookCustom() {
        fetch('/api/playbook', { cache: 'no-store', credentials: 'same-origin' })
            .then(function(r) { return r.json(); })
            .then(function(data) {
                if (data.success && Array.isArray(data.custom)) {
                    playbookCustomFromApi = data.custom;
                    playbookSites = playbookCustomFromApi.concat(playbookSitesBuiltIn);
                    renderPlaybookTagFilters();
                    renderPlaybookTabs();
                }
            })
            .catch(function() {});
    }

    let activePlaybookTagFilter = null;

    function getAllPlaybookTags() {
        const tags = new Set();
        playbookSites.forEach(s => {
            if (s.type === 'workflow') return;
            if (s.tags) s.tags.forEach(t => tags.add(t));
            if (s.type !== 'group' && s.isEssential) tags.add('Essential');
        });
        return Array.from(tags).sort();
    }

    function renderPlaybookTagFilters() {
        const filtersEl = document.getElementById('playbookTagFilters');
        if (!filtersEl) return;
        const tags = getAllPlaybookTags();
        filtersEl.innerHTML = `
            <button type="button" class="playbook-tag-filter ${activePlaybookTagFilter === null ? 'active' : ''}" data-tag-filter="all">All</button>
            ${tags.map(t => `
                <button type="button" class="playbook-tag-filter ${activePlaybookTagFilter === t ? 'active' : ''}" data-tag-filter="${escapeHtml(t)}">${escapeHtml(t)}</button>
            `).join('')}
        `;
        filtersEl.querySelectorAll('.playbook-tag-filter').forEach(btn => {
            btn.addEventListener('click', function() {
                const tag = this.getAttribute('data-tag-filter');
                activePlaybookTagFilter = tag === 'all' ? null : tag;
                renderPlaybookTagFilters();
                const searchVal = document.getElementById('playbookSearch')?.value || '';
                renderPlaybookTabs(searchVal);
            });
        });
    }

    function renderPlaybookTabs(filterText) {
        const tabsEl = document.getElementById('playbookTabs');
        if (!tabsEl) return;
        const q = (filterText || '').toLowerCase().trim();
        const filtered = playbookSites.filter(s => {
            if (s.type === 'workflow') {
                if (activePlaybookTagFilter) return false;
                if (!q) return true;
                return (s.name + ' ' + (s.content || '')).toLowerCase().indexOf(q) !== -1;
            }
            if (s.type === 'group') {
                if (activePlaybookTagFilter && (!s.tags || !s.tags.includes(activePlaybookTagFilter))) return false;
                if (!q) return true;
                const groupMatch = s.name.toLowerCase().indexOf(q) !== -1;
                const siteMatch = (s.sites || []).some(site => 
                    (site.name || '').toLowerCase().indexOf(q) !== -1 || 
                    (site.description || '').toLowerCase().indexOf(q) !== -1
                );
                return groupMatch || siteMatch;
            }
            if (activePlaybookTagFilter) {
                if (activePlaybookTagFilter === 'Essential') {
                    if (!s.isEssential) return false;
                } else if (!s.tags || !s.tags.includes(activePlaybookTagFilter)) {
                    return false;
                }
            }
            if (!q) return true;
            const searchable = (s.name + ' ' + (s.description || '') + ' ' + (s.tags || []).join(' ')).toLowerCase();
            return searchable.indexOf(q) !== -1;
        });
        tabsEl.innerHTML = filtered.map(s => {
            const editId = typeof s.id === 'string' ? s.id : '';
            const isCustomItem = playbookCustomFromApi.some(c => c.id === s.id);
            const customIdx = playbookCustomFromApi.findIndex(c => c.id === s.id);
            const canMoveUp = isCustomItem && customIdx > 0;
            const canMoveDown = isCustomItem && customIdx < playbookCustomFromApi.length - 1;
            const adminActions = (authState.is_admin && isCustomItem) ? `
                <div class="playbook-tab-actions flex flex-wrap items-center gap-1 mt-2" onclick="event.stopPropagation()">
                    ${canMoveUp ? `<button type="button" class="playbook-move-btn btn-cmd-neutral text-xs px-1.5 py-0.5" data-playbook-id="${escapeAttr(editId)}" data-dir="up" title="Move up">↑</button>` : ''}
                    ${canMoveDown ? `<button type="button" class="playbook-move-btn btn-cmd-neutral text-xs px-1.5 py-0.5" data-playbook-id="${escapeAttr(editId)}" data-dir="down" title="Move down">↓</button>` : ''}
                    <button type="button" class="playbook-edit-btn btn-cmd-neutral text-xs px-2 py-0.5" data-playbook-id="${escapeAttr(editId)}">Edit</button>
                    <button type="button" class="playbook-delete-btn btn-cmd-danger text-xs px-2 py-0.5" data-playbook-id="${escapeAttr(editId)}">Delete</button>
                </div>
            ` : '';
            if (s.type === 'workflow') {
                return `
                    <div class="playbook-tab-item playbook-tab-workflow" data-playbook-id="${escapeHtml(s.id)}" role="button" tabindex="0">
                        <div class="playbook-tab-name">${escapeHtml(s.name)}</div>
                        <div class="playbook-tab-desc text-xs text-secondary mt-1">Recommendations & overview</div>
                        ${adminActions}
                    </div>
                `;
            }
            if (s.type === 'group') {
                const groupTags = s.tags || [];
                const groupTagsHtml = groupTags.length ? `<div class="playbook-tab-tags flex flex-wrap gap-1 mt-1.5">${groupTags.map(t => `<span class="playbook-tab-tag">${escapeHtml(t)}</span>`).join('')}</div>` : '';
                return `
                    <div class="playbook-tab-item playbook-tab-group" data-playbook-id="${escapeHtml(s.id)}" role="button" tabindex="0">
                        <div class="playbook-tab-name">${escapeHtml(s.name)}</div>
                        <div class="playbook-tab-desc text-xs text-secondary mt-1">${(s.sites || []).length} sites</div>
                        ${groupTagsHtml}
                        ${adminActions}
                    </div>
                `;
            }
            const essentialBadge = s.isEssential ? '<span class="playbook-essential-badge">🔥</span>' : '';
            const displayTags = Array.from(new Set([...(s.isEssential ? ['Essential'] : []), ...(s.tags || [])]));
            const tagsHtml = displayTags.map(t => `<span class="playbook-tab-tag">${escapeHtml(t)}</span>`).join('');
            return `
                <div class="playbook-tab-item" data-playbook-id="${escapeHtml(s.id)}" role="button" tabindex="0">
                    <div class="flex items-center justify-between">
                        <div class="playbook-tab-name flex-1">${escapeHtml(s.name)}</div>
                        ${essentialBadge}
                    </div>
                    <div class="playbook-tab-desc text-xs text-secondary mt-1">${escapeHtml(s.url)}</div>
                    ${tagsHtml ? `<div class="playbook-tab-tags flex flex-wrap gap-1 mt-1.5">${tagsHtml}</div>` : ''}
                    ${adminActions}
                </div>
            `;
        }).join('');
        tabsEl.querySelectorAll('.playbook-tab-item').forEach(tab => {
            tab.addEventListener('click', (e) => {
                if (e.target.closest('.playbook-tab-actions')) return;
                showPlaybookSite(tab.getAttribute('data-playbook-id'));
            });
            tab.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); tab.click(); } });
        });
        tabsEl.querySelectorAll('.playbook-edit-btn').forEach(btn => {
            btn.addEventListener('click', function(e) {
                e.stopPropagation();
                const id = this.getAttribute('data-playbook-id');
                if (id != null) openPlaybookEditModal(id);
            });
        });
        tabsEl.querySelectorAll('.playbook-delete-btn').forEach(btn => {
            btn.addEventListener('click', function(e) {
                e.stopPropagation();
                const id = this.getAttribute('data-playbook-id');
                if (id != null) deletePlaybookItem(id);
            });
        });
        tabsEl.querySelectorAll('.playbook-move-btn').forEach(btn => {
            btn.addEventListener('click', function(e) {
                e.stopPropagation();
                const id = this.getAttribute('data-playbook-id');
                const dir = this.getAttribute('data-dir');
                if (id != null && dir === 'up') movePlaybookItemUp(id);
                if (id != null && dir === 'down') movePlaybookItemDown(id);
            });
        });
    }

    function showPlaybookSite(id) {
        const site = playbookSites.find(s => s.id === id);
        const contentEl = document.getElementById('playbookContent');
        if (!contentEl) return;
        document.querySelectorAll('#playbookTabs .playbook-tab-item').forEach(t => t.classList.remove('active'));
        const tab = document.querySelector(`#playbookTabs .playbook-tab-item[data-playbook-id="${id}"]`);
        if (tab) tab.classList.add('active');
        if (!site) {
            contentEl.removeAttribute('dir');
            contentEl.innerHTML = '<p class="text-secondary">Site not found.</p>';
            return;
        }
        contentEl.setAttribute('dir', site.dir === 'rtl' ? 'rtl' : 'ltr');
        if (site.type === 'workflow') {
            const raw = site.content || '';
            const looksLikeHtml = raw.trim().startsWith('<');
            let bodyHtml = raw;
            if (!looksLikeHtml && typeof marked !== 'undefined') {
                try { bodyHtml = marked.parse(raw); } catch (e) { bodyHtml = escapeHtml(raw); }
            } else if (!looksLikeHtml) {
                bodyHtml = escapeHtml(raw).replace(/\n/g, '<br>');
            }
            contentEl.innerHTML = `
                <h3 class="text-xl font-bold mb-4 accent-blue">${escapeHtml(site.name)}</h3>
                <div class="playbook-content playbook-workflow-content">${bodyHtml}</div>
            `;
            initPlaybookCopyButtons();
            return;
        }
        if (site.type === 'group') {
            function groupDescHtml(raw) {
                var r = raw || '';
                if (r.trim().startsWith('<')) return r;
                if (typeof marked !== 'undefined') { try { return marked.parse(r); } catch (e) { return escapeHtml(r); } }
                return escapeHtml(r).replace(/\n/g, '<br>');
            }
            var groupSitesWithHtml = (site.sites || []).map(function (s) {
                return { name: s.name, url: s.url, descHtml: groupDescHtml(s.description) };
            });
            contentEl.innerHTML = `
                <h3 class="text-xl font-bold mb-4 accent-blue">${escapeHtml(site.name)}</h3>
                <div class="space-y-6">
                    ${groupSitesWithHtml.map(s => {
                        const urlAttr = escapeAttr(s.url);
                        return `
                        <div class="playbook-group-site">
                            <h4 class="text-lg font-semibold mb-2 accent-blue">${escapeHtml(s.name)}</h4>
                            <div class="flex items-center gap-2 mb-2">
                                <span class="text-secondary font-mono text-sm">${escapeHtml(s.url)}</span>
                                <button type="button" class="copy-ioc-btn btn-cmd-neutral text-xs flex-shrink-0" onclick="copyToClipboard('${urlAttr}')" title="Copy URL">Copy</button>
                            </div>
                            <div class="playbook-section-content">${s.descHtml}</div>
                        </div>
                    `;
                    }).join('')}
                </div>
            `;
            return;
        }
        const urlAttr = escapeAttr(site.url);
        function toSectionHtml(raw) {
            var r = raw || '';
            var looksLikeHtml = r.trim().startsWith('<');
            if (looksLikeHtml) return r;
            if (typeof marked !== 'undefined') {
                try { return marked.parse(r); } catch (e) { return escapeHtml(r); }
            }
            return escapeHtml(r).replace(/\n/g, '<br>');
        }
        var descHtml = toSectionHtml(site.description);
        var examplesHtml = toSectionHtml(site.examples);
        var tipsHtml = toSectionHtml(site.tips);
        contentEl.innerHTML = `
            <h3 class="text-xl font-bold mb-2 accent-blue">${escapeHtml(site.name)}</h3>
            <div class="flex items-center gap-2 mb-6">
                <span class="text-secondary font-mono text-sm">${escapeHtml(site.url)}</span>
                <button type="button" class="copy-ioc-btn btn-cmd-neutral text-xs flex-shrink-0" onclick="copyToClipboard('${urlAttr}')" title="Copy URL">Copy</button>
            </div>
            <div class="playbook-section">
                <h4 class="playbook-section-title">About & Purpose</h4>
                <div class="playbook-section-content">${descHtml}</div>
            </div>
            <div class="playbook-divider"></div>
            <div class="playbook-section">
                <h4 class="playbook-section-title">Practical Examples</h4>
                <div class="playbook-section-content">${examplesHtml}</div>
            </div>
            <div class="playbook-divider"></div>
            <div class="playbook-section">
                <h4 class="playbook-section-title">Tips & Tricks</h4>
                <div class="playbook-section-content">${tipsHtml}</div>
            </div>
        `;
        initPlaybookCopyButtons();
    }

    function initPlaybookCopyButtons() {
        const contentEl = document.getElementById('playbookContent');
        if (!contentEl) return;
        contentEl.querySelectorAll('.playbook-code-block').forEach(block => {
            const code = block.querySelector('code');
            const btn = block.querySelector('.playbook-copy-btn');
            if (!code || !btn) return;
            btn.onclick = function() {
                const text = code.textContent || '';
                if (typeof copyToClipboard === 'function') {
                    copyToClipboard(text);
                } else if (navigator.clipboard && window.isSecureContext) {
                    navigator.clipboard.writeText(text).then(() => {}, () => {});
                }
                const orig = btn.textContent;
                btn.textContent = 'Copied!';
                setTimeout(() => { btn.textContent = orig; }, 1500);
            };
        });
    }

    (function initPlaybookSearch() {
        const searchEl = document.getElementById('playbookSearch');
        if (!searchEl) return;
        searchEl.addEventListener('input', function() {
            renderPlaybookTabs(this.value);
        });
        renderPlaybookTagFilters();
        const workflowContent = document.getElementById('playbookEditWorkflowContent');
        if (workflowContent) {
            workflowContent.addEventListener('input', updatePlaybookWorkflowPreview);
        }
    })();

    /* ---- expose on window for other modules ---- */
    window.loadPlaybookCustom = loadPlaybookCustom;
    window.renderPlaybookTagFilters = renderPlaybookTagFilters;
    window.renderPlaybookTabs = renderPlaybookTabs;

    Object.defineProperty(window, 'activePlaybookTagFilter', {
        get: function () { return activePlaybookTagFilter; },
        set: function (v) { activePlaybookTagFilter = v; },
        configurable: true
    });

    Object.defineProperty(window, 'playbookSites', {
        get: function () { return playbookSites; },
        set: function (v) { playbookSites = v; },
        configurable: true
    });

    Object.defineProperty(window, 'playbookCustomFromApi', {
        get: function () { return playbookCustomFromApi; },
        set: function (v) { playbookCustomFromApi = v; },
        configurable: true
    });

    Object.defineProperty(window, 'playbookSitesBuiltIn', {
        get: function () { return playbookSitesBuiltIn; },
        configurable: true
    });
})();
