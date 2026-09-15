"use strict";

/*
  Dorker
  Passive OSINT query builder for authorized external assessments.

  Compatibility goals:
  - htmlpreview.github.io
  - GitHub Pages
  - direct/local use
  - no frameworks
  - no build process
  - classic JavaScript syntax
*/

var MAX_QUERIES = 500;

var QUERY_PACKS = [
  {
    id: "attack-surface",
    name: "Attack Surface",
    description: "Public apps, portals, admin paths, remote access and support surfaces.",
    queries: [
      ["Application and portal paths", "Find indexed application and portal naming patterns.", "site:{domain} (inurl:portal OR inurl:app OR inurl:dashboard)"],
      ["Administrative interfaces", "Find indexed administrative or management paths for scope validation.", "site:{domain} (inurl:admin OR inurl:administrator OR inurl:management)"],
      ["Remote access references", "Find references to remote access, VPN and gateway surfaces.", "site:{domain} (inurl:remote OR inurl:vpn OR inurl:gateway)"],
      ["Support portals", "Find support, helpdesk and service portal paths.", "site:{domain} (inurl:support OR inurl:helpdesk OR inurl:service)"],
      ["Console and workspace paths", "Find indexed console and workspace-style applications.", "site:{domain} (inurl:console OR inurl:workspace OR inurl:webapp)"]
    ]
  },
  {
    id: "authentication",
    name: "Authentication",
    description: "Login, SSO, federation and account-management surfaces.",
    queries: [
      ["Login pages", "Find common sign-in URL patterns.", "site:{domain} (inurl:login OR inurl:signin OR inurl:sign-in)"],
      ["Authentication paths", "Find identity and authentication-related paths.", "site:{domain} (inurl:auth OR inurl:authentication OR inurl:identity)"],
      ["SSO and federation", "Find SSO, SAML and federation references.", "site:{domain} (inurl:sso OR inurl:saml OR inurl:federation)"],
      ["OAuth and OIDC", "Find public references to OAuth and OpenID Connect flows.", "site:{domain} (inurl:oauth OR inurl:openid OR inurl:oidc)"],
      ["Account management", "Find account, registration and password-reset surfaces.", "site:{domain} (inurl:account OR inurl:register OR inurl:reset)"]
    ]
  },
  {
    id: "non-production",
    name: "Dev / Test",
    description: "Development, testing, staging, QA, UAT and sandbox references.",
    queries: [
      ["Development environments", "Find development-system naming patterns.", "site:{domain} (inurl:dev OR inurl:development)"],
      ["Testing environments", "Find test-system naming patterns.", "site:{domain} (inurl:test OR inurl:testing)"],
      ["Staging environments", "Find staging and pre-production references.", "site:{domain} (inurl:stage OR inurl:staging OR inurl:preprod)"],
      ["QA and UAT", "Find quality-assurance and user-acceptance-test references.", "site:{domain} (inurl:qa OR inurl:uat)"],
      ["Sandbox and demo", "Find sandbox, demo and proof-of-concept references.", "site:{domain} (inurl:sandbox OR inurl:demo OR inurl:poc)"]
    ]
  },
  {
    id: "api",
    name: "API / Developer",
    description: "API paths, Swagger, OpenAPI, GraphQL and developer documentation.",
    queries: [
      ["API paths", "Find indexed API paths and API-titled pages.", "site:{domain} (inurl:api OR intitle:\"API\")"],
      ["Swagger and OpenAPI", "Find public API specifications and documentation.", "site:{domain} (inurl:swagger OR inurl:openapi OR \"OpenAPI\")"],
      ["Developer portals", "Find public developer portals and docs.", "site:{domain} (inurl:developer OR inurl:developers OR inurl:docs)"],
      ["GraphQL references", "Find public GraphQL references.", "site:{domain} (inurl:graphql OR \"GraphQL\")"],
      ["API documentation phrases", "Find pages explicitly describing API documentation.", "site:{domain} (\"API documentation\" OR \"developer documentation\" OR \"API reference\")"]
    ]
  },
  {
    id: "documents",
    name: "Technical Documents",
    description: "Architecture, network, deployment, operations and security documentation.",
    queries: [
      ["Architecture documents", "Find architecture and network-diagram references.", "site:{domain} (\"architecture diagram\" OR \"network diagram\" OR \"system architecture\")"],
      ["Deployment documents", "Find deployment, implementation and installation guides.", "site:{domain} (\"deployment guide\" OR \"implementation guide\" OR \"installation guide\")"],
      ["Operations documents", "Find runbooks and operational documentation.", "site:{domain} (\"runbook\" OR \"operations guide\" OR \"support guide\")"],
      ["Security documents", "Find security, incident-response and continuity documentation.", "site:{domain} (\"security policy\" OR \"incident response\" OR \"business continuity\")"],
      ["Technical PDFs", "Find PDFs containing infrastructure or network terminology.", "site:{domain} filetype:pdf (\"architecture\" OR \"infrastructure\" OR \"network\")"],
      ["Technical presentations", "Find presentations containing technical design information.", "site:{domain} (filetype:ppt OR filetype:pptx) (\"architecture\" OR \"infrastructure\" OR \"technical\")"]
    ]
  },
  {
    id: "files",
    name: "Indexed Files",
    description: "Publicly indexed document and data-file formats.",
    queries: [
      ["PDF documents", "Find indexed PDF documents.", "site:{domain} filetype:pdf"],
      ["Word documents", "Find indexed Word documents.", "site:{domain} (filetype:doc OR filetype:docx)"],
      ["Spreadsheets", "Find indexed spreadsheets and CSV files.", "site:{domain} (filetype:xls OR filetype:xlsx OR filetype:csv)"],
      ["Presentations", "Find indexed presentation files.", "site:{domain} (filetype:ppt OR filetype:pptx)"],
      ["Text and logs", "Find publicly indexed plaintext and log-format content.", "site:{domain} (filetype:txt OR filetype:log)"],
      ["Internal-use terminology", "Find documents using common internal-document classifications.", "site:{domain} (\"internal use only\" OR \"confidential\" OR \"do not distribute\")"]
    ]
  },
  {
    id: "directories",
    name: "Directory Exposure",
    description: "Common directory-listing and file-repository indicators.",
    queries: [
      ["Index of", "Find pages with common directory-listing titles.", "site:{domain} intitle:\"index of\""],
      ["Directory listing", "Find pages explicitly titled as directory listings.", "site:{domain} intitle:\"directory listing\""],
      ["Parent directory", "Find pages containing common parent-directory navigation text.", "site:{domain} \"parent directory\""],
      ["Repository paths", "Find indexed file, document and download paths.", "site:{domain} (inurl:files OR inurl:documents OR inurl:downloads)"]
    ]
  },
  {
    id: "cloud",
    name: "Cloud / SaaS",
    description: "Public references to cloud platforms, identity providers and common SaaS.",
    queries: [
      ["AWS references", "Find public references to common AWS-hosted resources.", "site:{domain} (\"amazonaws.com\" OR \"cloudfront.net\" OR \"aws.amazon.com\")"],
      ["Azure references", "Find public references to common Azure-hosted services.", "site:{domain} (\"azurewebsites.net\" OR \"blob.core.windows.net\" OR \"azure.com\")"],
      ["Microsoft 365 references", "Find public Microsoft 365 and SharePoint references.", "site:{domain} (\"sharepoint.com\" OR \"office.com\" OR \"microsoftonline.com\")"],
      ["Identity provider references", "Find public references to common identity platforms.", "site:{domain} (\"okta.com\" OR \"auth0.com\" OR \"onelogin.com\")"],
      ["Common SaaS references", "Find public references to common enterprise SaaS platforms.", "site:{domain} (\"salesforce.com\" OR \"servicenow.com\" OR \"atlassian.net\")"]
    ]
  },
  {
    id: "public-code",
    name: "Public Code",
    description: "Public code-hosting and developer-community references.",
    queries: [
      ["GitHub references", "Search indexed GitHub pages for the target domain.", "site:github.com \"{domain}\""],
      ["GitLab references", "Search indexed GitLab pages for the target domain.", "site:gitlab.com \"{domain}\""],
      ["Stack Overflow references", "Search indexed Stack Overflow pages for the target domain.", "site:stackoverflow.com \"{domain}\""],
      ["Repository terminology", "Find public pages connecting the domain with source-code terminology.", "\"{domain}\" (\"GitHub\" OR \"GitLab\" OR \"source code\" OR \"repository\")"]
    ]
  },
  {
    id: "technology",
    name: "Technology Intelligence",
    description: "Public clues about infrastructure, identity, cloud and technologies in use.",
    queries: [
      ["Platform references", "Find pages that identify technologies used by the organization.", "site:{domain} (\"powered by\" OR \"built with\" OR \"hosted on\")"],
      ["Infrastructure technologies", "Find public mentions of common infrastructure platforms.", "site:{domain} (\"VMware\" OR \"Nutanix\" OR \"Citrix\" OR \"Cisco\")"],
      ["Cloud technologies", "Find public mentions of major cloud platforms.", "site:{domain} (\"AWS\" OR \"Amazon Web Services\" OR \"Microsoft Azure\" OR \"Google Cloud\")"],
      ["Identity technologies", "Find public references to common identity platforms.", "site:{domain} (\"Entra ID\" OR \"Azure AD\" OR \"Okta\" OR \"Active Directory\")"],
      ["Hiring technology clues", "Use recruiting content to identify technologies associated with the organization.", "\"{domain}\" (\"engineer\" OR \"administrator\" OR \"developer\") (\"AWS\" OR \"Azure\" OR \"Linux\" OR \"Windows\")"]
    ]
  },
  {
    id: "organization",
    name: "Organization / Scope",
    description: "Subsidiaries, acquisitions, brands, partners and portal references.",
    queries: [
      ["Subsidiaries", "Find public references to subsidiaries and divisions.", "\"{domain}\" (\"subsidiary\" OR \"subsidiaries\" OR \"division\")"],
      ["Acquisitions", "Find acquisitions and mergers that may create scope questions.", "\"{domain}\" (\"acquired\" OR \"acquisition\" OR \"merger\")"],
      ["Partners", "Find public business and technology partner references.", "\"{domain}\" (\"partner\" OR \"technology partner\" OR \"integration partner\")"],
      ["Related brands", "Find public references to related brands and operating names.", "\"{domain}\" (\"brand\" OR \"operating as\" OR \"formerly known as\")"],
      ["Business portals", "Find references to customer, employee and vendor portals.", "\"{domain}\" (\"customer portal\" OR \"employee portal\" OR \"vendor portal\")"]
    ]
  }
];

var NOISE_EXCLUSIONS = [
  "-inurl:blog",
  "-inurl:news",
  "-inurl:press",
  "-inurl:events",
  "-inurl:careers"
];

var state = {
  generated: [],
  filtered: []
};

var el = {};

function byId(id) {
  return document.getElementById(id);
}

function init() {
  el.targets = byId("targets");
  el.moduleList = byId("moduleList");
  el.moduleSummary = byId("moduleSummary");
  el.exclusions = byId("exclusions");
  el.reduceNoise = byId("reduceNoise");
  el.excludeWww = byId("excludeWww");
  el.generateBtn = byId("generateBtn");
  el.resetBtn = byId("resetBtn");
  el.resultSearch = byId("resultSearch");
  el.copyAllBtn = byId("copyAllBtn");
  el.exportBtn = byId("exportBtn");
  el.resultCount = byId("resultCount");
  el.message = byId("message");
  el.emptyState = byId("emptyState");
  el.results = byId("results");

  renderModules();
  bindEvents();
  updateModuleSummary();
}

function bindEvents() {
  el.generateBtn.onclick = generateQueries;
  el.resetBtn.onclick = resetApp;
  el.resultSearch.onkeyup = filterResults;
  el.copyAllBtn.onclick = copyAllVisible;
  el.exportBtn.onclick = exportVisible;

  el.moduleList.onchange = function () {
    updateModuleSummary();
  };

  el.targets.onkeydown = function (event) {
    event = event || window.event;

    if ((event.ctrlKey || event.metaKey) && event.keyCode === 13) {
      generateQueries();
    }
  };
}

function renderModules() {
  var html = "";
  var i;
  var pack;

  for (i = 0; i < QUERY_PACKS.length; i += 1) {
    pack = QUERY_PACKS[i];

    html += '<label class="module-row">';
    html += '<input class="module-checkbox" type="checkbox" value="' + escapeHtml(pack.id) + '" checked>';
    html += '<span>';
    html += '<span class="module-name">' + escapeHtml(pack.name) + '</span>';
    html += '<span class="module-desc">' + escapeHtml(pack.description) + '</span>';
    html += '</span>';
    html += '</label>';
  }

  el.moduleList.innerHTML = html;
}

function getSelectedPackIds() {
  var inputs = el.moduleList.getElementsByTagName("input");
  var selected = [];
  var i;

  for (i = 0; i < inputs.length; i += 1) {
    if (inputs[i].checked) {
      selected.push(inputs[i].value);
    }
  }

  return selected;
}

function updateModuleSummary() {
  var selected = getSelectedPackIds();
  var total = 0;
  var i;

  for (i = 0; i < QUERY_PACKS.length; i += 1) {
    if (contains(selected, QUERY_PACKS[i].id)) {
      total += QUERY_PACKS[i].queries.length;
    }
  }

  el.moduleSummary.innerHTML =
    selected.length + " of " + QUERY_PACKS.length +
    " modules selected, " + total + " query templates.";
}

function contains(arr, value) {
  var i;

  for (i = 0; i < arr.length; i += 1) {
    if (arr[i] === value) {
      return true;
    }
  }

  return false;
}

function parseDomains(value) {
  var raw = value.split(/[\n,]+/);
  var result = [];
  var seen = {};
  var i;
  var domain;

  for (i = 0; i < raw.length; i += 1) {
    domain = normalizeDomain(raw[i]);

    if (domain && !seen[domain]) {
      seen[domain] = true;
      result.push(domain);
    }
  }

  return result;
}

function normalizeDomain(value) {
  var domain = trim(value).toLowerCase();

  if (!domain) {
    return "";
  }

  domain = domain.replace(/^https?:\/\//i, "");
  domain = domain.replace(/^\/\//, "");
  domain = domain.split("/")[0];
  domain = domain.split("?")[0];
  domain = domain.split("#")[0];
  domain = domain.replace(/:\d+$/, "");
  domain = domain.replace(/^\*\./, "");
  domain = domain.replace(/\.$/, "");

  if (domain.indexOf("www.") === 0) {
    domain = domain.substring(4);
  }

  if (!isValidDomain(domain)) {
    return "";
  }

  return domain;
}

function isValidDomain(domain) {
  var labels;
  var i;

  if (!domain || domain.length > 253 || domain.indexOf(".") === -1) {
    return false;
  }

  labels = domain.split(".");

  if (labels.length < 2) {
    return false;
  }

  for (i = 0; i < labels.length; i += 1) {
    if (
      labels[i].length < 1 ||
      labels[i].length > 63 ||
      !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/i.test(labels[i])
    ) {
      return false;
    }
  }

  return true;
}

function parseExclusions(value) {
  var parts = value.split(/[,\n]+/);
  var out = [];
  var seen = {};
  var i;
  var formatted;

  for (i = 0; i < parts.length; i += 1) {
    formatted = formatExclusion(parts[i]);

    if (formatted && !seen[formatted]) {
      seen[formatted] = true;
      out.push(formatted);
    }
  }

  return out;
}

function formatExclusion(value) {
  var term = trim(value);
  var clean;

  if (!term) {
    return "";
  }

  if (term.charAt(0) === "-") {
    term = term.substring(1);
  }

  if (/^inurl:/i.test(term) || /^site:/i.test(term)) {
    return "-" + term;
  }

  if (term.indexOf(" ") !== -1) {
    clean = term.replace(/"/g, "");
    return '-"' + clean + '"';
  }

  return "-" + term;
}

function replaceDomain(template, domain) {
  return template.split("{domain}").join(domain);
}

function applyExclusions(query, domain, custom) {
  var additions = [];
  var targetScoped = query.indexOf("site:" + domain) !== -1;
  var i;

  if (targetScoped && el.reduceNoise.checked) {
    for (i = 0; i < NOISE_EXCLUSIONS.length; i += 1) {
      additions.push(NOISE_EXCLUSIONS[i]);
    }
  }

  if (targetScoped && el.excludeWww.checked) {
    additions.push("-site:www." + domain);
  }

  for (i = 0; i < custom.length; i += 1) {
    additions.push(custom[i]);
  }

  if (additions.length > 0) {
    return query + " " + additions.join(" ");
  }

  return query;
}

function generateQueries() {
  var domains = parseDomains(el.targets.value);
  var selected = getSelectedPackIds();
  var custom = parseExclusions(el.exclusions.value);
  var generated = [];
  var i;
  var j;
  var k;
  var pack;
  var q;
  var query;
  var truncated = false;

  clearMessage();

  if (domains.length === 0) {
    showMessage("Enter at least one valid target domain, such as example.com.");
    return;
  }

  if (selected.length === 0) {
    showMessage("Select at least one query module.");
    return;
  }

  for (i = 0; i < domains.length; i += 1) {
    for (j = 0; j < QUERY_PACKS.length; j += 1) {
      pack = QUERY_PACKS[j];

      if (!contains(selected, pack.id)) {
        continue;
      }

      for (k = 0; k < pack.queries.length; k += 1) {
        if (generated.length >= MAX_QUERIES) {
          truncated = true;
          break;
        }

        q = pack.queries[k];
        query = replaceDomain(q[2], domains[i]);
        query = applyExclusions(query, domains[i], custom);

        generated.push({
          id: "q" + generated.length,
          domain: domains[i],
          packId: pack.id,
          packName: pack.name,
          title: q[0],
          why: q[1],
          query: query
        });
      }

      if (truncated) {
        break;
      }
    }

    if (truncated) {
      break;
    }
  }

  state.generated = generated;
  state.filtered = generated.slice(0);

  el.resultSearch.value = "";
  el.resultSearch.disabled = false;
  el.copyAllBtn.disabled = false;
  el.exportBtn.disabled = false;

  if (truncated) {
    showMessage("Generation was capped at " + MAX_QUERIES + " queries.");
  }

  renderResults();
}

function filterResults() {
  var term = trim(el.resultSearch.value).toLowerCase();
  var filtered = [];
  var i;
  var item;
  var searchable;

  if (!term) {
    state.filtered = state.generated.slice(0);
    renderResults();
    return;
  }

  for (i = 0; i < state.generated.length; i += 1) {
    item = state.generated[i];

    searchable =
      item.domain + " " +
      item.packName + " " +
      item.title + " " +
      item.why + " " +
      item.query;

    if (searchable.toLowerCase().indexOf(term) !== -1) {
      filtered.push(item);
    }
  }

  state.filtered = filtered;
  renderResults();
}

function renderResults() {
  var groups = {};
  var order = [];
  var html = "";
  var i;
  var item;
  var key;

  el.resultCount.innerHTML = state.filtered.length;

  if (state.generated.length === 0) {
    el.emptyState.style.display = "block";
    el.results.innerHTML = "";
    return;
  }

  el.emptyState.style.display = "none";

  if (state.filtered.length === 0) {
    el.results.innerHTML = '<div class="empty">No matching queries.</div>';
    return;
  }

  for (i = 0; i < state.filtered.length; i += 1) {
    item = state.filtered[i];
    key = item.packId;

    if (!groups[key]) {
      groups[key] = {
        name: item.packName,
        items: []
      };
      order.push(key);
    }

    groups[key].items.push(item);
  }

  for (i = 0; i < order.length; i += 1) {
    html += renderGroup(groups[order[i]]);
  }

  el.results.innerHTML = html;
  bindQueryButtons();
}

function renderGroup(group) {
  var html = "";
  var i;

  html += '<section class="group">';
  html += '<h3 class="group-title">' + escapeHtml(group.name) + ' (' + group.items.length + ')</h3>';

  for (i = 0; i < group.items.length; i += 1) {
    html += renderQuery(group.items[i]);
  }

  html += '</section>';
  return html;
}

function renderQuery(item) {
  var encoded = encodeURIComponent(item.query);
  var google = "https://www.google.com/search?q=" + encoded;
  var bing = "https://www.bing.com/search?q=" + encoded;
  var duck = "https://duckduckgo.com/?q=" + encoded;
  var html = "";

  html += '<article class="query">';
  html += '<div class="query-header">';
  html += '<div class="query-title">' + escapeHtml(item.title) + '</div>';
  html += '<div class="query-target">' + escapeHtml(item.domain) + '</div>';
  html += '</div>';
  html += '<div class="query-why">' + escapeHtml(item.why) + '</div>';
  html += '<div class="query-code">' + escapeHtml(item.query) + '</div>';
  html += '<div class="query-actions">';
  html += '<a href="' + google + '" target="_blank" rel="noopener noreferrer">Google</a>';
  html += '<a href="' + bing + '" target="_blank" rel="noopener noreferrer">Bing</a>';
  html += '<a href="' + duck + '" target="_blank" rel="noopener noreferrer">DuckDuckGo</a>';
  html += '<button type="button" class="copy-one" data-id="' + escapeHtml(item.id) + '">Copy</button>';
  html += '</div>';
  html += '</article>';

  return html;
}

function bindQueryButtons() {
  var buttons = el.results.getElementsByTagName("button");
  var i;

  for (i = 0; i < buttons.length; i += 1) {
    if (buttons[i].className === "copy-one") {
      buttons[i].onclick = function () {
        var id = this.getAttribute("data-id");
        var item = findById(id);

        if (item) {
          copyText(item.query);
        }
      };
    }
  }
}

function findById(id) {
  var i;

  for (i = 0; i < state.generated.length; i += 1) {
    if (state.generated[i].id === id) {
      return state.generated[i];
    }
  }

  return null;
}

function buildExport(items) {
  var lines = [];
  var i;
  var currentGroup = "";

  lines.push("DORKER - EXTERNAL ASSESSMENT OSINT");
  lines.push("==================================");
  lines.push("");
  lines.push("Generated: " + new Date().toString());
  lines.push("Queries: " + items.length);
  lines.push("");
  lines.push("Authorized assessment use only.");
  lines.push("");

  for (i = 0; i < items.length; i += 1) {
    if (items[i].packName !== currentGroup) {
      currentGroup = items[i].packName;
      lines.push("");
      lines.push("[ " + currentGroup.toUpperCase() + " ]");
      lines.push("");
    }

    lines.push(items[i].title);
    lines.push("Target: " + items[i].domain);
    lines.push("Purpose: " + items[i].why);
    lines.push(items[i].query);
    lines.push("");
  }

  return lines.join("\n");
}

function copyAllVisible() {
  if (state.filtered.length === 0) {
    return;
  }

  copyText(buildExport(state.filtered));
}

function copyText(text) {
  if (navigator.clipboard && window.isSecureContext) {
    navigator.clipboard.writeText(text).then(
      function () {
        showMessage("Copied to clipboard.");
      },
      function () {
        fallbackCopy(text);
      }
    );
    return;
  }

  fallbackCopy(text);
}

function fallbackCopy(text) {
  var box = document.createElement("textarea");
  var ok = false;

  box.value = text;
  box.style.position = "fixed";
  box.style.left = "-9999px";
  box.style.top = "0";

  document.body.appendChild(box);
  box.focus();
  box.select();

  try {
    ok = document.execCommand("copy");
  } catch (err) {
    ok = false;
  }

  document.body.removeChild(box);

  if (ok) {
    showMessage("Copied to clipboard.");
  } else {
    showMessage("Clipboard access was blocked. Copy the query manually.");
  }
}

function exportVisible() {
  var text;
  var blob;
  var url;
  var a;
  var fileName;

  if (state.filtered.length === 0) {
    return;
  }

  text = buildExport(state.filtered);
  blob = new Blob([text], { type: "text/plain;charset=utf-8" });
  url = window.URL.createObjectURL(blob);

  fileName = "dorker-queries-" + formatDate(new Date()) + ".txt";

  a = document.createElement("a");
  a.href = url;
  a.download = fileName;

  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);

  window.setTimeout(function () {
    window.URL.revokeObjectURL(url);
  }, 1000);
}

function resetApp() {
  var inputs = el.moduleList.getElementsByTagName("input");
  var i;

  el.targets.value = "";
  el.exclusions.value = "";
  el.reduceNoise.checked = false;
  el.excludeWww.checked = false;
  el.resultSearch.value = "";

  for (i = 0; i < inputs.length; i += 1) {
    inputs[i].checked = true;
  }

  state.generated = [];
  state.filtered = [];

  el.resultSearch.disabled = true;
  el.copyAllBtn.disabled = true;
  el.exportBtn.disabled = true;
  el.resultCount.innerHTML = "0";
  el.emptyState.style.display = "block";
  el.results.innerHTML = "";

  clearMessage();
  updateModuleSummary();
}

function showMessage(text) {
  el.message.innerHTML = escapeHtml(text);
  el.message.style.display = "block";
}

function clearMessage() {
  el.message.innerHTML = "";
  el.message.style.display = "none";
}

function trim(value) {
  return String(value).replace(/^\s+|\s+$/g, "");
}

function formatDate(date) {
  var year = date.getFullYear();
  var month = date.getMonth() + 1;
  var day = date.getDate();

  if (month < 10) {
    month = "0" + month;
  }

  if (day < 10) {
    day = "0" + day;
  }

  return year + "-" + month + "-" + day;
}

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", init);
} else {
  init();
}
