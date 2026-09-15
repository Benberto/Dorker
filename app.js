```javascript
"use strict";

/*
 * Dorker v2
 * External Assessment OSINT Query Builder
 *
 * Client-side only.
 * No automated search requests.
 * No scanning.
 * No target interaction.
 */

const MAX_QUERIES = 500;

const QUERY_PACKS = [
  {
    id: "attack-surface",
    name: "Attack Surface",
    description: "Discover indexed web applications, portals, and externally visible services.",
    queries: [
      {
        title: "Application and portal paths",
        why: "Looks for indexed paths commonly associated with public applications and portals.",
        query: 'site:{domain} (inurl:portal OR inurl:app OR inurl:dashboard)'
      },
      {
        title: "Administrative interfaces",
        why: "Surfaces indexed references to administrative or management interfaces for validation.",
        query: 'site:{domain} (inurl:admin OR inurl:administrator OR inurl:management)'
      },
      {
        title: "Remote access references",
        why: "Finds indexed pages associated with remote-access and gateway terminology.",
        query: 'site:{domain} (inurl:remote OR inurl:vpn OR inurl:gateway)'
      },
      {
        title: "Support and service portals",
        why: "Identifies externally indexed support, helpdesk, and service portal paths.",
        query: 'site:{domain} (inurl:support OR inurl:helpdesk OR inurl:service)'
      },
      {
        title: "Alternate application paths",
        why: "Looks for applications exposed through common web-app naming conventions.",
        query: 'site:{domain} (inurl:webapp OR inurl:console OR inurl:workspace)'
      }
    ]
  },

  {
    id: "authentication",
    name: "Authentication",
    description: "Identify indexed login, SSO, identity, and account-management surfaces.",
    queries: [
      {
        title: "Login surfaces",
        why: "Discovers pages with URL patterns commonly used for interactive authentication.",
        query: 'site:{domain} (inurl:login OR inurl:signin OR inurl:sign-in)'
      },
      {
        title: "Authentication paths",
        why: "Looks for indexed authentication and identity-related application paths.",
        query: 'site:{domain} (inurl:auth OR inurl:authentication OR inurl:identity)'
      },
      {
        title: "SSO and federation",
        why: "Identifies indexed references to SSO and common federation terminology.",
        query: 'site:{domain} (inurl:sso OR inurl:saml OR inurl:federation)'
      },
      {
        title: "OAuth and OIDC",
        why: "Finds public pages and documentation referencing modern authentication flows.",
        query: 'site:{domain} (inurl:oauth OR inurl:openid OR inurl:oidc)'
      },
      {
        title: "Account management",
        why: "Surfaces indexed account, registration, and password-reset interfaces.",
        query: 'site:{domain} (inurl:account OR inurl:register OR inurl:reset)'
      }
    ]
  },

  {
    id: "non-production",
    name: "Dev / Test Environments",
    description: "Look for publicly indexed references to non-production environments.",
    queries: [
      {
        title: "Development environments",
        why: "Searches for URL patterns associated with development systems.",
        query: 'site:{domain} (inurl:dev OR inurl:development)'
      },
      {
        title: "Testing environments",
        why: "Searches for publicly indexed test-system naming conventions.",
        query: 'site:{domain} (inurl:test OR inurl:testing)'
      },
      {
        title: "Staging environments",
        why: "Looks for staging or pre-production references in indexed URLs.",
        query: 'site:{domain} (inurl:stage OR inurl:staging OR inurl:preprod)'
      },
      {
        title: "QA and UAT",
        why: "Finds URL patterns associated with quality assurance and user acceptance testing.",
        query: 'site:{domain} (inurl:qa OR inurl:uat)'
      },
      {
        title: "Sandbox and demo systems",
        why: "Looks for sandbox, demo, and proof-of-concept environments exposed to indexing.",
        query: 'site:{domain} (inurl:sandbox OR inurl:demo OR inurl:poc)'
      }
    ]
  },

  {
    id: "api",
    name: "API & Developer Surface",
    description: "Discover indexed APIs, developer portals, and public API documentation.",
    queries: [
      {
        title: "API paths",
        why: "Identifies indexed paths explicitly associated with APIs.",
        query: 'site:{domain} (inurl:api OR intitle:"API")'
      },
      {
        title: "Swagger and OpenAPI",
        why: "Looks for publicly indexed API documentation frameworks and specifications.",
        query: 'site:{domain} (inurl:swagger OR inurl:openapi OR "OpenAPI")'
      },
      {
        title: "Developer portals",
        why: "Finds documentation and portals intended for developers and integrations.",
        query: 'site:{domain} (inurl:developer OR inurl:developers OR inurl:docs)'
      },
      {
        title: "GraphQL references",
        why: "Surfaces public GraphQL documentation and references.",
        query: 'site:{domain} (inurl:graphql OR "GraphQL")'
      },
      {
        title: "API documentation phrases",
        why: "Searches indexed pages for explicit API documentation terminology.",
        query: 'site:{domain} ("API documentation" OR "developer documentation" OR "API reference")'
      }
    ]
  },

  {
    id: "documents",
    name: "Technical Documents",
    description: "Identify publicly indexed technical, architectural, operational, and policy documents.",
    queries: [
      {
        title: "Architecture documentation",
        why: "Looks for publicly indexed architecture and infrastructure documentation.",
        query: 'site:{domain} ("architecture diagram" OR "network diagram" OR "system architecture")'
      },
      {
        title: "Deployment documentation",
        why: "Finds guides describing deployment or implementation processes.",
        query: 'site:{domain} ("deployment guide" OR "implementation guide" OR "installation guide")'
      },
      {
        title: "Operations documentation",
        why: "Searches for runbooks and operational documentation that may describe business systems.",
        query: 'site:{domain} ("runbook" OR "operations guide" OR "support guide")'
      },
      {
        title: "Security documentation",
        why: "Finds publicly available security and continuity documentation.",
        query: 'site:{domain} ("security policy" OR "incident response" OR "business continuity")'
      },
      {
        title: "Technical PDFs",
        why: "Looks for PDF documents containing infrastructure or architecture terminology.",
        query: 'site:{domain} filetype:pdf ("architecture" OR "infrastructure" OR "network")'
      },
      {
        title: "Technical presentations",
        why: "Looks for publicly indexed slide decks containing technical design information.",
        query: 'site:{domain} (filetype:ppt OR filetype:pptx) ("architecture" OR "infrastructure" OR "technical")'
      }
    ]
  },

  {
    id: "files",
    name: "Indexed Files",
    description: "Find publicly indexed business and technical document formats.",
    queries: [
      {
        title: "PDF documents",
        why: "Enumerates publicly indexed PDF documents associated with the target.",
        query: 'site:{domain} filetype:pdf'
      },
      {
        title: "Word documents",
        why: "Looks for publicly indexed Microsoft Word documents.",
        query: 'site:{domain} (filetype:doc OR filetype:docx)'
      },
      {
        title: "Spreadsheet documents",
        why: "Looks for publicly indexed spreadsheet files that may provide organizational context.",
        query: 'site:{domain} (filetype:xls OR filetype:xlsx OR filetype:csv)'
      },
      {
        title: "Presentations",
        why: "Finds publicly indexed presentation files.",
        query: 'site:{domain} (filetype:ppt OR filetype:pptx)'
      },
      {
        title: "Text and log references",
        why: "Looks for indexed plaintext and log-format content exposed through normal web indexing.",
        query: 'site:{domain} (filetype:txt OR filetype:log)'
      },
      {
        title: "Internal-use terminology",
        why: "Finds indexed pages and documents containing common internal-document classifications.",
        query: 'site:{domain} ("internal use only" OR "confidential" OR "do not distribute")'
      }
    ]
  },

  {
    id: "directories",
    name: "Directory Exposure",
    description: "Look for publicly indexed directory-listing indicators.",
    queries: [
      {
        title: "Index of",
        why: "Finds pages indexed with the common directory-listing title.",
        query: 'site:{domain} intitle:"index of"'
      },
      {
        title: "Directory listing",
        why: "Looks for pages explicitly titled as directory listings.",
        query: 'site:{domain} intitle:"directory listing"'
      },
      {
        title: "Parent directory",
        why: "Searches for indexed pages containing common parent-directory navigation text.",
        query: 'site:{domain} "parent directory"'
      },
      {
        title: "File repository paths",
        why: "Looks for indexed paths that may represent document or download repositories.",
        query: 'site:{domain} (inurl:files OR inurl:documents OR inurl:downloads)'
      }
    ]
  },

  {
    id: "cloud",
    name: "Cloud & SaaS Footprint",
    description: "Identify public references to common cloud and SaaS providers.",
    queries: [
      {
        title: "AWS references",
        why: "Finds public target pages referencing common AWS-hosted resources.",
        query: 'site:{domain} ("amazonaws.com" OR "cloudfront.net" OR "aws.amazon.com")'
      },
      {
        title: "Microsoft cloud references",
        why: "Looks for references to common Azure and Microsoft-hosted services.",
        query: 'site:{domain} ("azurewebsites.net" OR "blob.core.windows.net" OR "azure.com")'
      },
      {
        title: "Microsoft 365 references",
        why: "Identifies public references to Microsoft 365 and SharePoint services.",
        query: 'site:{domain} ("sharepoint.com" OR "office.com" OR "microsoftonline.com")'
      },
      {
        title: "Identity provider references",
        why: "Looks for public references to third-party identity platforms.",
        query: 'site:{domain} ("okta.com" OR "auth0.com" OR "onelogin.com")'
      },
      {
        title: "Common SaaS references",
        why: "Surfaces references to commonly used SaaS platforms that can help characterize the external environment.",
        query: 'site:{domain} ("salesforce.com" OR "servicenow.com" OR "atlassian.net")'
      }
    ]
  },

  {
    id: "public-code",
    name: "Public Code Footprint",
    description: "Find public code, repository, and developer-community references associated with the domain.",
    queries: [
      {
        title: "GitHub references",
        why: "Searches public GitHub pages indexed with references to the target domain.",
        query: 'site:github.com "{domain}"'
      },
      {
        title: "GitLab references",
        why: "Searches publicly indexed GitLab pages for references to the target domain.",
        query: 'site:gitlab.com "{domain}"'
      },
      {
        title: "Stack Overflow references",
        why: "Finds developer discussions that reference the organization's domain.",
        query: 'site:stackoverflow.com "{domain}"'
      },
      {
        title: "Public code terminology",
        why: "Looks for public pages connecting the target with repository or source-code terminology.",
        query: '"{domain}" ("GitHub" OR "GitLab" OR "source code" OR "repository")'
      }
    ]
  },

  {
    id: "technology",
    name: "Technology Intelligence",
    description: "Collect passive clues about technologies, platforms, and infrastructure in use.",
    queries: [
      {
        title: "Platform references",
        why: "Looks for public pages that explicitly identify technologies used by the organization.",
        query: 'site:{domain} ("powered by" OR "built with" OR "hosted on")'
      },
      {
        title: "Infrastructure technologies",
        why: "Finds public mentions of common enterprise infrastructure technologies.",
        query: 'site:{domain} ("VMware" OR "Nutanix" OR "Citrix" OR "Cisco")'
      },
      {
        title: "Cloud technologies",
        why: "Finds public mentions of major cloud platforms.",
        query: 'site:{domain} ("AWS" OR "Amazon Web Services" OR "Microsoft Azure" OR "Google Cloud")'
      },
      {
        title: "Identity technologies",
        why: "Looks for public references to common identity and access technologies.",
        query: 'site:{domain} ("Entra ID" OR "Azure AD" OR "Okta" OR "Active Directory")'
      },
      {
        title: "Careers technology clues",
        why: "Uses publicly indexed recruiting content to identify technologies associated with the organization.",
        query: '"{domain}" ("engineer" OR "administrator" OR "developer") ("AWS" OR "Azure" OR "Linux" OR "Windows")'
      }
    ]
  },

  {
    id: "organization",
    name: "Organization & Scope",
    description: "Gather passive information useful for understanding related brands, subsidiaries, and external scope.",
    queries: [
      {
        title: "Subsidiary references",
        why: "Looks for publicly indexed relationships between the target and subsidiaries or divisions.",
        query: '"{domain}" ("subsidiary" OR "subsidiaries" OR "division")'
      },
      {
        title: "Acquisition references",
        why: "Finds public references to acquisitions and acquired organizations that may affect assessment scope.",
        query: '"{domain}" ("acquired" OR "acquisition" OR "merger")'
      },
      {
        title: "Partner references",
        why: "Looks for public references to business and technology partners.",
        query: '"{domain}" ("partner" OR "technology partner" OR "integration partner")'
      },
      {
        title: "Brand references",
        why: "Finds references to related brands and operating names.",
        query: '"{domain}" ("brand" OR "operating as" OR "formerly known as")'
      },
      {
        title: "External service references",
        why: "Looks for publicly documented references to portals, services, and externally hosted business functions.",
        query: '"{domain}" ("customer portal" OR "employee portal" OR "vendor portal")'
      }
    ]
  }
];

const NOISE_EXCLUSIONS = [
  "-inurl:blog",
  "-inurl:news",
  "-inurl:press",
  "-inurl:events",
  "-inurl:careers"
];

const state = {
  generated: [],
  filtered: []
};

const elements = {};

document.addEventListener("DOMContentLoaded", init);

function init() {
  cacheElements();
  renderModuleList();
  bindEvents();
  updateModuleSummary();
}

function cacheElements() {
  elements.targets = document.getElementById("targets");
  elements.moduleList = document.getElementById("moduleList");
  elements.moduleSummary = document.getElementById("moduleSummary");

  elements.exclusions = document.getElementById("exclusions");
  elements.reduceNoise = document.getElementById("reduceNoise");
  elements.excludeWww = document.getElementById("excludeWww");

  elements.generateBtn = document.getElementById("generateBtn");
  elements.resetBtn = document.getElementById("resetBtn");

  elements.resultSearch = document.getElementById("resultSearch");
  elements.copyAllBtn = document.getElementById("copyAllBtn");
  elements.exportBtn = document.getElementById("exportBtn");

  elements.resultCount = document.getElementById("resultCount");
  elements.resultSubtitle = document.getElementById("resultSubtitle");

  elements.emptyState = document.getElementById("emptyState");
  elements.results = document.getElementById("results");
  elements.notice = document.getElementById("notice");
  elements.toast = document.getElementById("toast");
}

function bindEvents() {
  elements.generateBtn.addEventListener("click", generateQueries);
  elements.resetBtn.addEventListener("click", resetApplication);

  elements.resultSearch.addEventListener(
    "input",
    filterResults
  );

  elements.copyAllBtn.addEventListener(
    "click",
    copyAllVisible
  );

  elements.exportBtn.addEventListener(
    "click",
    exportVisibleQueries
  );

  elements.moduleList.addEventListener(
    "change",
    updateModuleSummary
  );

  elements.targets.addEventListener("input", () => {
    elements.targets.classList.remove("error");
  });

  elements.targets.addEventListener("keydown", event => {
    if ((event.ctrlKey || event.metaKey) && event.key === "Enter") {
      generateQueries();
    }
  });
}

function renderModuleList() {
  const fragment = document.createDocumentFragment();

  QUERY_PACKS.forEach(pack => {
    const label = document.createElement("label");
    label.className = "module-option";

    const checkbox = document.createElement("input");

    checkbox.type = "checkbox";
    checkbox.className = "module-checkbox";
    checkbox.value = pack.id;
    checkbox.checked = true;

    const copy = document.createElement("div");
    copy.className = "module-copy";

    const name = document.createElement("div");
    name.className = "module-name";
    name.textContent = pack.name;

    const description = document.createElement("div");
    description.className = "module-description";
    description.textContent = pack.description;

    copy.append(name, description);

    const count = document.createElement("span");
    count.className = "module-count";
    count.textContent = pack.queries.length;

    label.append(checkbox, copy, count);
    fragment.appendChild(label);
  });

  elements.moduleList.appendChild(fragment);
}

function updateModuleSummary() {
  const selected = getSelectedPackIds();

  const queryCount = QUERY_PACKS
    .filter(pack => selected.includes(pack.id))
    .reduce(
      (total, pack) => total + pack.queries.length,
      0
    );

  elements.moduleSummary.textContent =
    `${selected.length}/${QUERY_PACKS.length} • ${queryCount} templates`;
}

function getSelectedPackIds() {
  return Array.from(
    document.querySelectorAll(".module-checkbox:checked")
  ).map(input => input.value);
}

function generateQueries() {
  clearNotice();

  const domains = parseDomains(elements.targets.value);

  if (domains.length === 0) {
    elements.targets.classList.add("error");

    showNotice(
      "Enter at least one valid target domain, such as example.com."
    );

    elements.targets.focus();
    return;
  }

  const selectedPackIds = getSelectedPackIds();

  if (selectedPackIds.length === 0) {
    showNotice(
      "Select at least one assessment module."
    );

    return;
  }

  const selectedPacks = QUERY_PACKS.filter(pack =>
    selectedPackIds.includes(pack.id)
  );

  const customExclusions = parseExclusions(
    elements.exclusions.value
  );

  const generated = [];

  let truncated = false;

  outer:
  for (const domain of domains) {
    for (const pack of selectedPacks) {
      for (const template of pack.queries) {
        if (generated.length >= MAX_QUERIES) {
          truncated = true;
          break outer;
        }

        let query = applyTemplate(
          template.query,
          domain
        );

        query = applyOptionalExclusions(
          query,
          domain,
          customExclusions
        );

        generated.push({
          id: `${pack.id}-${generated.length}`,
          domain,
          packId: pack.id,
          packName: pack.name,
          title: template.title,
          why: template.why,
          query
        });
      }
    }
  }

  state.generated = generated;
  state.filtered = [...generated];

  elements.resultSearch.value = "";
  elements.resultSearch.disabled = false;
  elements.copyAllBtn.disabled = false;
  elements.exportBtn.disabled = false;

  if (truncated) {
    showNotice(
      `Query generation was capped at ${MAX_QUERIES} results. Reduce the number of targets or assessment modules to generate the remaining combinations.`
    );
  }

  renderResults();
}

function parseDomains(value) {
  const values = value
    .split(/[\n,]+/)
    .map(value => normalizeDomain(value))
    .filter(Boolean);

  return [...new Set(values)];
}

function normalizeDomain(value) {
  let domain = value.trim().toLowerCase();

  if (!domain) {
    return null;
  }

  domain = domain
    .replace(/^https?:\/\//i, "")
    .replace(/^\/\//, "")
    .split("/")[0]
    .split("?")[0]
    .split("#")[0]
    .replace(/:\d+$/, "")
    .replace(/^\*\./, "")
    .replace(/\.$/, "");

  if (domain.startsWith("www.")) {
    domain = domain.slice(4);
  }

  if (!isValidDomain(domain)) {
    return null;
  }

  return domain;
}

function isValidDomain(domain) {
  if (
    !domain ||
    domain.length > 253 ||
    !domain.includes(".")
  ) {
    return false;
  }

  const labels = domain.split(".");

  if (labels.length < 2) {
    return false;
  }

  return labels.every(label => {
    if (
      label.length < 1 ||
      label.length > 63
    ) {
      return false;
    }

    return (
      /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/i
        .test(label)
    );
  });
}

function parseExclusions(value) {
  return [
    ...new Set(
      value
        .split(/[,\n]+/)
        .map(value => value.trim())
        .filter(Boolean)
        .map(formatExclusion)
        .filter(Boolean)
    )
  ];
}

function formatExclusion(value) {
  let term = value.trim();

  if (!term) {
    return null;
  }

  if (term.startsWith("-")) {
    term = term.slice(1);
  }

  if (/^inurl:/i.test(term)) {
    return `-${term}`;
  }

  if (/^site:/i.test(term)) {
    return `-${term}`;
  }

  if (term.includes(" ")) {
    const cleaned = term.replace(/"/g, "");

    return `-"${cleaned}"`;
  }

  return `-${term}`;
}

function applyTemplate(template, domain) {
  return template
    .replaceAll("{domain}", domain)
    .replace(/\s+/g, " ")
    .trim();
}

function applyOptionalExclusions(
  query,
  domain,
  customExclusions
) {
  const additions = [];

  /*
   * Only append site-specific noise controls to queries that
   * are actually scoped to the target's own domain.
   *
   * This prevents GitHub/GitLab/etc. footprinting queries from
   * receiving irrelevant target-site exclusions.
   */
  const targetScoped =
    query.includes(`site:${domain}`);

  if (
    targetScoped &&
    elements.reduceNoise.checked
  ) {
    additions.push(...NOISE_EXCLUSIONS);
  }

  if (
    targetScoped &&
    elements.excludeWww.checked
  ) {
    additions.push(`-site:www.${domain}`);
  }

  additions.push(...customExclusions);

  if (additions.length === 0) {
    return query;
  }

  return `${query} ${additions.join(" ")}`.trim();
}

function filterResults() {
  const search =
    elements.resultSearch.value
      .trim()
      .toLowerCase();

  if (!search) {
    state.filtered = [...state.generated];
  } else {
    state.filtered = state.generated.filter(item => {
      const searchable = [
        item.domain,
        item.packName,
        item.title,
        item.why,
        item.query
      ]
        .join(" ")
        .toLowerCase();

      return searchable.includes(search);
    });
  }

  renderResults();
}

function renderResults() {
  const results = state.filtered;

  elements.resultCount.textContent = results.length;

  if (state.generated.length === 0) {
    showEmptyState();
    return;
  }

  elements.emptyState.hidden = true;
  elements.results.hidden = false;

  elements.resultSubtitle.textContent =
    state.filtered.length === state.generated.length
      ? `${uniqueDomains(state.generated).length} target(s) • ${uniqueGroups(state.generated).length} assessment module(s)`
      : `${state.filtered.length} of ${state.generated.length} generated queries visible`;

  if (results.length === 0) {
    elements.results.innerHTML = `
      <div class="empty-state">
        <div>
          <div class="empty-icon">0</div>

          <h2>No matching queries</h2>

          <p>
            Change or clear the result filter to show the
            generated assessment queries.
          </p>
        </div>
      </div>
    `;

    return;
  }

  const grouped = groupByPack(results);

  const html = grouped
    .map(group => renderGroup(group))
    .join("");

  elements.results.innerHTML = html;

  bindQueryActions();
}

function showEmptyState() {
  elements.emptyState.hidden = false;
  elements.results.hidden = true;
  elements.results.innerHTML = "";

  elements.resultCount.textContent = "0";
  elements.resultSubtitle.textContent =
    "Configure an assessment to begin.";

  elements.resultSearch.disabled = true;
  elements.copyAllBtn.disabled = true;
  elements.exportBtn.disabled = true;
}

function groupByPack(items) {
  const map = new Map();

  items.forEach(item => {
    if (!map.has(item.packId)) {
      map.set(item.packId, {
        id: item.packId,
        name: item.packName,
        items: []
      });
    }

    map.get(item.packId).items.push(item);
  });

  return Array.from(map.values());
}

function renderGroup(group) {
  return `
    <section class="result-group">
      <div class="group-heading">
        <div class="group-name">
          <span class="group-dot"></span>
          ${escapeHtml(group.name)}
        </div>

        <div class="group-count">
          ${group.items.length} queries
        </div>
      </div>

      <div class="query-list">
        ${group.items.map(renderQueryCard).join("")}
      </div>
    </section>
  `;
}

function renderQueryCard(item) {
  const encoded =
    encodeURIComponent(item.query);

  const google =
    `https://www.google.com/search?q=${encoded}`;

  const bing =
    `https://www.bing.com/search?q=${encoded}`;

  const duckDuckGo =
    `https://duckduckgo.com/?q=${encoded}`;

  return `
    <article
      class="query-card"
      data-query-id="${escapeHtml(item.id)}"
    >
      <div class="query-top">
        <div class="query-meta">
          <div class="query-title">
            ${escapeHtml(item.title)}
          </div>

          <div class="target-badge">
            ${escapeHtml(item.domain)}
          </div>
        </div>

        <div class="query-why">
          ${escapeHtml(item.why)}
        </div>

        <div class="query-code">${escapeHtml(item.query)}</div>
      </div>

      <div class="query-actions">
        <a
          class="action-link"
          href="${google}"
          target="_blank"
          rel="noopener noreferrer"
        >
          Google ↗
        </a>

        <a
          class="action-link"
          href="${bing}"
          target="_blank"
          rel="noopener noreferrer"
        >
          Bing ↗
        </a>

        <a
          class="action-link"
          href="${duckDuckGo}"
          target="_blank"
          rel="noopener noreferrer"
        >
          DuckDuckGo ↗
        </a>

        <button
          type="button"
          class="copy-query"
          data-copy-id="${escapeHtml(item.id)}"
        >
          Copy
        </button>
      </div>
    </article>
  `;
}

function bindQueryActions() {
  elements.results
    .querySelectorAll("[data-copy-id]")
    .forEach(button => {
      button.addEventListener("click", async () => {
        const id =
          button.getAttribute("data-copy-id");

        const item =
          state.generated.find(
            query => query.id === id
          );

        if (!item) {
          return;
        }

        const success =
          await copyText(item.query);

        if (success) {
          showToast("Query copied to clipboard.");
        }
      });
    });
}

async function copyAllVisible() {
  if (state.filtered.length === 0) {
    return;
  }

  const text =
    buildTextExport(state.filtered);

  const success =
    await copyText(text);

  if (success) {
    showToast(
      `${state.filtered.length} queries copied to clipboard.`
    );
  }
}

function exportVisibleQueries() {
  if (state.filtered.length === 0) {
    return;
  }

  const content =
    buildTextExport(state.filtered);

  const blob =
    new Blob(
      [content],
      {
        type: "text/plain;charset=utf-8"
      }
    );

  const url =
    URL.createObjectURL(blob);

  const anchor =
    document.createElement("a");

  const firstDomain =
    state.filtered[0]?.domain || "assessment";

  const date =
    new Date()
      .toISOString()
      .slice(0, 10);

  anchor.href = url;
  anchor.download =
    `dorker-${firstDomain}-${date}.txt`;

  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();

  URL.revokeObjectURL(url);

  showToast(
    `${state.filtered.length} queries exported.`
  );
}

function buildTextExport(items) {
  const groups =
    groupByPack(items);

  const targets =
    uniqueDomains(items);

  const lines = [
    "DORKER - EXTERNAL ASSESSMENT OSINT",
    "==================================",
    "",
    `Generated: ${new Date().toLocaleString()}`,
    `Targets: ${targets.join(", ")}`,
    `Queries: ${items.length}`,
    "",
    "Authorized assessment use only.",
    "Search results are investigative leads and require validation.",
    ""
  ];

  groups.forEach(group => {
    lines.push(
      "",
      `[ ${group.name.toUpperCase()} ]`,
      "-".repeat(group.name.length + 4),
      ""
    );

    group.items.forEach((item, index) => {
      lines.push(
        `${index + 1}. ${item.title}`,
        `Target: ${item.domain}`,
        `Purpose: ${item.why}`,
        "",
        item.query,
        ""
      );
    });
  });

  return lines.join("\n");
}

async function copyText(text) {
  try {
    if (
      navigator.clipboard &&
      window.isSecureContext
    ) {
      await navigator.clipboard.writeText(text);
      return true;
    }

    const textarea =
      document.createElement("textarea");

    textarea.value = text;
    textarea.style.position = "fixed";
    textarea.style.opacity = "0";

    document.body.appendChild(textarea);

    textarea.focus();
    textarea.select();

    const success =
      document.execCommand("copy");

    textarea.remove();

    if (!success) {
      throw new Error("Clipboard copy failed.");
    }

    return true;
  } catch (error) {
    console.error(error);

    showNotice(
      "Your browser blocked clipboard access. You can still select and copy the query manually."
    );

    return false;
  }
}

function resetApplication() {
  elements.targets.value = "";
  elements.exclusions.value = "";

  elements.reduceNoise.checked = false;
  elements.excludeWww.checked = false;

  elements.resultSearch.value = "";

  document
    .querySelectorAll(".module-checkbox")
    .forEach(input => {
      input.checked = true;
    });

  elements.targets.classList.remove("error");

  state.generated = [];
  state.filtered = [];

  clearNotice();
  updateModuleSummary();
  showEmptyState();

  elements.targets.focus();
}

function uniqueDomains(items) {
  return [
    ...new Set(
      items.map(item => item.domain)
    )
  ];
}

function uniqueGroups(items) {
  return [
    ...new Set(
      items.map(item => item.packId)
    )
  ];
}

function showNotice(message) {
  elements.notice.textContent = message;
  elements.notice.classList.add("visible");
}

function clearNotice() {
  elements.notice.textContent = "";
  elements.notice.classList.remove("visible");
}

let toastTimer;

function showToast(message) {
  clearTimeout(toastTimer);

  elements.toast.textContent = message;
  elements.toast.classList.add("visible");

  toastTimer = setTimeout(() => {
    elements.toast.classList.remove("visible");
  }, 2200);
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}
```
