````markdown
# Dorker

**Dorker** is a client-side External Assessment OSINT Query Builder designed to help security professionals build structured search-engine queries during authorized external security assessments.

Rather than manually remembering dozens of advanced search operators, Dorker organizes passive reconnaissance queries into assessment-focused modules and generates them automatically for one or more target domains.

> Dorker does not scan targets, exploit systems, authenticate to services, or automatically send search requests. It generates passive search queries that an assessor can review and execute manually.

---

## Features

### External Assessment Query Packs

Dorker currently includes more than 50 query templates organized into the following assessment modules:

- Attack Surface
- Authentication
- Dev / Test Environments
- API & Developer Surface
- Technical Documents
- Indexed Files
- Directory Exposure
- Cloud & SaaS Footprint
- Public Code Footprint
- Technology Intelligence
- Organization & Scope

Each generated query includes:

- Query title
- Assessment purpose
- Target domain
- Generated search query
- Google search link
- Bing search link
- DuckDuckGo search link
- Copy-to-clipboard support

---

## Example Queries

Dorker can generate queries such as:

```text
site:example.com (inurl:login OR inurl:signin OR inurl:sign-in)
````

```text
site:example.com (inurl:dev OR inurl:development)
```

```text
site:example.com (inurl:swagger OR inurl:openapi OR "OpenAPI")
```

```text
site:example.com ("architecture diagram" OR "network diagram" OR "system architecture")
```

```text
site:example.com ("amazonaws.com" OR "cloudfront.net" OR "aws.amazon.com")
```

```text
site:github.com "example.com"
```

These searches identify information that has already been publicly indexed by search engines. A search result should be treated as an investigative lead rather than evidence of a security vulnerability.

---

# Why Dorker Exists

External assessments often begin with passive reconnaissance.

An assessor may need to understand:

* What public applications exist?
* Where are authentication portals located?
* Are development or staging systems publicly referenced?
* Is API documentation indexed?
* What technical documentation is publicly available?
* Which cloud or SaaS platforms appear to be in use?
* Does the organization have a public code footprint?
* What technologies are associated with the organization?
* Are there subsidiaries, acquired companies, or alternate brands that may affect assessment scope?

Search engines can provide valuable information for answering these questions, but manually constructing advanced queries becomes repetitive.

Dorker organizes these searches into repeatable assessment workflows.

---

# Assessment Modules

## Attack Surface

Searches for publicly indexed application and service paths such as:

* Portals
* Dashboards
* Administrative interfaces
* Remote-access references
* Support portals
* Management interfaces

---

## Authentication

Searches for public authentication-related surfaces including:

* Login pages
* Sign-in pages
* Authentication endpoints
* SSO
* SAML
* OAuth
* OpenID Connect
* Account-management interfaces

---

## Dev / Test Environments

Looks for naming conventions commonly associated with non-production environments:

* Development
* Testing
* Staging
* Pre-production
* QA
* UAT
* Sandbox
* Demo
* Proof-of-concept systems

A search result does not establish that the environment is vulnerable or within assessment scope. Validate authorization before interacting with discovered systems.

---

## API & Developer Surface

Searches for publicly indexed:

* API paths
* Swagger documentation
* OpenAPI documentation
* Developer portals
* GraphQL references
* API documentation

---

## Technical Documents

Searches for documents that may provide useful organizational or architectural context:

* Architecture diagrams
* Network diagrams
* Deployment guides
* Implementation guides
* Runbooks
* Operations guides
* Security documentation
* Infrastructure presentations

---

## Indexed Files

Searches common publicly indexed file formats including:

* PDF
* DOC / DOCX
* XLS / XLSX
* CSV
* PPT / PPTX
* TXT
* LOG

It can also identify documents containing common internal-document classifications such as:

```text
"internal use only"
```

or:

```text
"confidential"
```

The presence of an indexed document does not automatically mean its publication is unintended.

---

## Directory Exposure

Searches for common indicators of publicly indexed directory listings and file repositories.

Examples include:

```text
intitle:"index of"
```

and:

```text
"parent directory"
```

---

## Cloud & SaaS Footprint

Looks for references to common external platforms such as:

* Amazon Web Services
* Microsoft Azure
* Microsoft 365
* SharePoint
* Okta
* Auth0
* OneLogin
* Salesforce
* ServiceNow
* Atlassian

These results can help characterize an organization's publicly visible technology footprint.

---

## Public Code Footprint

Searches public development platforms and communities for references to the target organization.

Current searches include:

* GitHub
* GitLab
* Stack Overflow

Example:

```text
site:github.com "example.com"
```

Dorker does not access private repositories or bypass repository access controls.

---

## Technology Intelligence

Uses public web content to identify technology references associated with the organization.

Examples include:

* Cloud platforms
* Identity providers
* Virtualization technologies
* Infrastructure platforms
* Operating systems
* Technologies listed in job postings

Recruiting pages can be particularly useful for identifying technologies that an organization actively operates.

---

## Organization & Scope

Provides searches that can help identify:

* Subsidiaries
* Divisions
* Acquisitions
* Mergers
* Business partners
* Related brands
* Customer portals
* Employee portals
* Vendor portals

These searches can help an assessor identify potential scope questions that should be confirmed with the customer before testing.

---

# Query Options

## Reduce Marketing Noise

Dorker can optionally append common exclusions:

```text
-inurl:blog
-inurl:news
-inurl:press
-inurl:events
-inurl:careers
```

This can reduce irrelevant marketing results when investigating technical attack surface.

The option is disabled by default because those sections can still contain useful OSINT.

---

## De-emphasize the Primary WWW Host

Dorker can optionally add:

```text
-site:www.example.com
```

to queries scoped to the target domain.

This can sometimes make less obvious indexed content easier to identify.

---

## Custom Exclusions

Custom exclusions can be entered as comma-separated values.

Example:

```text
blog, careers, marketing
```

Dorker converts these to:

```text
-blog -careers -marketing
```

Multi-word phrases are automatically quoted.

Example:

```text
privacy policy
```

becomes:

```text
-"privacy policy"
```

URL exclusions can also be entered:

```text
inurl:blog
```

which becomes:

```text
-inurl:blog
```

---

# Multiple Targets

Multiple authorized domains can be supplied, one per line:

```text
example.com
example.org
example.net
```

Dorker generates the selected assessment query set for each target.

For browser performance and usability, generation is capped at 500 queries per run.

---

# Filtering Results

After generating queries, use the result filter to search across:

* Module
* Target
* Query title
* Assessment purpose
* Query contents

For example:

```text
swagger
```

will display queries associated with Swagger/API discovery.

---

# Exporting Assessment Queries

Dorker supports:

### Copy All

Copies the currently visible query set to the clipboard.

### Export TXT

Exports the currently visible query set as a text file containing:

* Generation timestamp
* Assessment targets
* Module names
* Query titles
* Query purposes
* Search queries

Result filtering also affects export output, allowing individual assessment modules or topics to be exported separately.

---

# Running Dorker Locally

Dorker has no dependencies and requires no build process.

The repository only requires:

```text
index.html
app.js
README.md
```

Clone the repository:

```bash
git clone https://github.com/Benberto/Dorker.git
```

Move into the directory:

```bash
cd Dorker
```

You can then open:

```text
index.html
```

directly in a browser.

For the best clipboard behavior, serve the project through localhost or GitHub Pages.

For example, with Python:

```bash
python3 -m http.server 8000
```

Then visit:

```text
http://localhost:8000
```

---

# GitHub Pages Deployment

GitHub Pages is the recommended way to host Dorker.

In the GitHub repository:

1. Open **Settings**.
2. Select **Pages**.
3. Under **Build and deployment**, select **Deploy from a branch**.
4. Select the `main` branch.
5. Select `/ (root)`.
6. Save the configuration.

Once GitHub Pages deploys the repository, Dorker should be available at:

```text
https://benberto.github.io/Dorker/
```

This is preferable to using an HTML preview service because the application runs directly from the repository's GitHub Pages deployment.

---

# Project Structure

```text
Dorker/
├── index.html
├── app.js
└── README.md
```

### `index.html`

Contains:

* Application layout
* Styling
* Assessment controls
* Result interface

### `app.js`

Contains:

* Query library
* Query templates
* Target validation
* Assessment module logic
* Query generation
* Result filtering
* Search-engine links
* Clipboard support
* TXT export

No third-party JavaScript libraries are required.

---

# Privacy

Dorker runs entirely inside the user's browser.

It does not:

* Send target domains to a Dorker backend
* Store assessment targets
* Maintain a database
* Create accounts
* Collect analytics
* Automatically execute searches
* Automatically crawl websites
* Scan target systems
* Authenticate to discovered services

When an assessor selects a search-engine link, the query is submitted directly to that search engine in the user's browser.

Normal search-engine logging and privacy policies still apply.

---

# Authorized Use

Dorker is intended for:

* Authorized external security assessments
* Penetration-testing reconnaissance
* Security research
* Attack-surface reviews
* Defensive OSINT
* Exposure assessments
* Security education

Only assess systems and organizations for which you have appropriate authorization.

Discovery of a hostname, application, document, organization, or third-party service does not establish that the asset is authorized for active testing.

Always validate discovered assets against the applicable assessment scope and rules of engagement.

---

# Important Assessment Principle

**Discovery is not proof of vulnerability.**

Examples:

Finding:

```text
stage.example.com
```

does not prove the staging environment is insecure.

Finding:

```text
site:example.com intitle:"index of"
```

does not prove sensitive information is accessible.

Finding a public cloud reference does not prove that the associated cloud resource belongs to the organization or is within scope.

Dorker is designed to generate investigative leads.

Those leads should be validated independently.

---

# Search Engine Differences

Search operators are interpreted differently by different search engines.

Dorker currently provides links for:

* Google
* Bing
* DuckDuckGo

A query that produces useful results in one search engine may produce different results in another.

Using multiple search engines can provide broader passive OSINT coverage.

---

# Roadmap

Potential future improvements include:

* Custom query templates
* User-defined assessment packs
* Query favorites
* Local browser persistence
* JSON query-pack import/export
* Additional search engines
* Subdomain-focused workflows
* Expanded corporate OSINT
* Improved assessment reporting exports
* Query tagging
* Operator compatibility indicators
* Per-engine query variants
* Light/dark theme support
* More passive external-assessment modules

---

# Contributing

Suggestions, query improvements, bug reports, and pull requests are welcome.

When proposing new query templates, they should ideally include:

1. A clear assessment objective.
2. A description of why the query is useful.
3. A passive search-engine query.
4. An appropriate assessment category.
5. Minimal duplicate coverage with existing templates.

The goal is to keep Dorker useful as an organized assessment tool rather than simply becoming a large unstructured list of search operators.

---

# Disclaimer

Dorker is provided for educational purposes and authorized security assessment activities.

The project generates search-engine queries only.

Users are responsible for ensuring that their activities comply with applicable laws, contracts, assessment scopes, organizational policies, and rules of engagement.

The maintainers are not responsible for misuse of the software.

---

## Author

**Ben Bertagnole**

GitHub: `@Benberto`

---

## Dorker

**Passive OSINT. Better queries. Better external assessments.**

```
```
