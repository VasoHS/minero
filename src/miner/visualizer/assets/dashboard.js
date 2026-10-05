/* Visualizer · GitHub CodeQL Miner — tablero autocontenido.
 *
 * Lee el documento del Analyzer embebido en
 * <script id="analyzer-data" type="application/json"> y monta todo el tablero
 * dentro de #app. Sin fetch, sin CDN, sin frameworks y sin inyección de HTML
 * con datos del documento (solo createElement/textContent).
 *
 * Nota de empaquetado: este archivo se embebe literalmente dentro de una
 * etiqueta de script en el HTML generado, por lo que nunca debe contener la
 * secuencia de cierre de esa etiqueta.
 */
(function () {
  "use strict";

  // ---------------------------------------------------------------------------
  // Constantes del contrato
  // ---------------------------------------------------------------------------

  var SEVERITIES = ["Critical", "High", "Medium", "Low", "Negligible", "Unknown"];
  var ROW_LIMIT = 300;

  var COLS = [
    { key: "repo", label: "Repositorio", type: "text" },
    { key: "status", label: "Estado", type: "text" },
    { key: "score", label: "Nota", type: "num" },
    { key: "severity_weighted_average", label: "Gravedad media", type: "num" },
    { key: "severity_median", label: "Mediana", type: "num" },
    { key: "worst_severity", label: "Peor", type: "sev" },
    { key: "critical", label: "Critical", type: "num" },
    { key: "high", label: "High", type: "num" },
    { key: "vulnerabilities", label: "Vulns", type: "num" },
    { key: "findings", label: "Findings", type: "num" },
    { key: "components", label: "Comp.", type: "num" },
    { key: "vulns_per_component", label: "Vulns/comp", type: "num" },
    { key: "findings_per_component", label: "Findings/comp", type: "num" },
    { key: "fixed_version_share", label: "Reparable", type: "num" }
  ];

  // ---------------------------------------------------------------------------
  // Estado del tablero
  // ---------------------------------------------------------------------------

  var state = {
    doc: null,
    filters: null,
    sort: { key: "score", dir: "desc" },
    selectedRepo: null,
    scatterDensity: false,
    view: null,
    contentEl: null,
    drillEl: null,
    statusEl: null,
    tipEl: null,
    tipTarget: null
  };

  var updateTimer = null;
  var booted = false;

  // ---------------------------------------------------------------------------
  // Utilidades de DOM
  // ---------------------------------------------------------------------------

  function applyAttrs(node, attrs) {
    if (!attrs) return;
    Object.keys(attrs).forEach(function (key) {
      var value = attrs[key];
      if (value == null) return;
      if (key === "text") node.textContent = String(value);
      else if (key === "class" || key === "className") node.setAttribute("class", String(value));
      else if (key === "style" && typeof value === "object") {
        Object.keys(value).forEach(function (prop) { node.style[prop] = value[prop]; });
      } else if (key === "checked" || key === "disabled" || key === "selected") node[key] = !!value;
      else if (key === "value") node.value = String(value);
      else node.setAttribute(key, String(value));
    });
  }

  function appendChildren(node, children) {
    (children || []).forEach(function (child) {
      if (child == null || child === false) return;
      if (typeof child === "string" || typeof child === "number") {
        node.appendChild(document.createTextNode(String(child)));
      } else {
        node.appendChild(child);
      }
    });
  }

  function el(tag, attrs, children) {
    var node = document.createElement(tag);
    applyAttrs(node, attrs);
    appendChildren(node, children);
    return node;
  }

  function svgEl(tag, attrs, children) {
    var node = document.createElementNS("http://www.w3.org/2000/svg", tag);
    applyAttrs(node, attrs);
    appendChildren(node, children);
    return node;
  }

  function clear(node) {
    if (!node) return;
    while (node.firstChild) node.removeChild(node.firstChild);
  }

  function sinDatos(mensaje) {
    return el("p", { class: "empty", text: mensaje || "Sin datos." });
  }

  // ---------------------------------------------------------------------------
  // Formato y matemáticas
  // ---------------------------------------------------------------------------

  function num(x) { var n = Number(x); return isFinite(n) ? n : 0; }

  function fmtInt(x) { var n = Number(x); return isFinite(n) ? String(Math.round(n)) : "0"; }
  function fmt1(x) { var n = Number(x); return isFinite(n) ? n.toFixed(1) : "—"; }
  function fmt2(x) { var n = Number(x); return isFinite(n) ? n.toFixed(2) : "—"; }
  function fmt4(x) { var n = Number(x); return isFinite(n) ? n.toFixed(4) : "—"; }
  function fmtIntOrDash(x) { return x == null ? "—" : fmtInt(x); }
  function fmt1OrDash(x) { return x == null ? "—" : fmt1(x); }
  function fmt2OrDash(x) { return x == null ? "—" : fmt2(x); }
  function fmt4OrDash(x) { return x == null ? "—" : fmt4(x); }
  function pct(x, digits) {
    var d = digits == null ? 1 : digits;
    return (num(x) * 100).toFixed(d) + "%";
  }
  function fmtPctOrDash(x) { return x == null ? "—" : pct(x); }

  function byRepo(a, b) {
    var x = String(a.repo), y = String(b.repo);
    return x < y ? -1 : x > y ? 1 : 0;
  }

  // ---------------------------------------------------------------------------
  // Severidad
  // ---------------------------------------------------------------------------

  function isCanonical(s) { return SEVERITIES.indexOf(String(s)) >= 0; }

  function canonical(s) {
    var v = String(s);
    return isCanonical(v) ? v : "Unknown";
  }

  function sevIndex(s) {
    var i = SEVERITIES.indexOf(canonical(s));
    return i < 0 ? SEVERITIES.length - 1 : i;
  }

  function sevClass(s) { return "sev-" + canonical(s).toLowerCase(); }
  function sevColorVar(s) { return "var(--sev-" + canonical(s).toLowerCase() + ")"; }

  function emptySeverityMap() {
    var map = {};
    SEVERITIES.forEach(function (s) { map[s] = 0; });
    return map;
  }

  function sevBadge(s) {
    var c = canonical(s);
    return el("span", { class: "badge " + sevClass(c), text: c });
  }

  function prefersReduced() {
    try {
      return !!(window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches);
    } catch (e) { return false; }
  }

  // ---------------------------------------------------------------------------
  // Lectura del documento y filtros
  // ---------------------------------------------------------------------------

  function readDocument() {
    var node = document.getElementById("analyzer-data");
    if (!node) return null;
    try {
      return JSON.parse(node.textContent);
    } catch (error) {
      return null;
    }
  }

  function defaultFilters() {
    var sev = {};
    SEVERITIES.forEach(function (s) { sev[s] = true; });
    return { repoQuery: "", severities: sev, packageType: "all", language: "all" };
  }

  function filtersActive(f) {
    if (f.repoQuery) return true;
    if (f.packageType !== "all") return true;
    if (f.language !== "all") return true;
    for (var i = 0; i < SEVERITIES.length; i++) {
      if (f.severities[SEVERITIES[i]] === false) return true;
    }
    return false;
  }

  // Recolecta la información de repositorio de todos los datasets que la traen.
  function collectRepos(doc) {
    var ds = doc.datasets || {};
    var map = {};
    var order = [];

    function ensure(name) {
      if (!name) return null;
      if (!map[name]) {
        map[name] = { repo: name, status: "", languages: [], components: 0, findings: 0, vulnerabilities: 0 };
        order.push(name);
      }
      return map[name];
    }

    (ds.repositories || []).forEach(function (r) {
      var e = ensure(r.repo); if (!e) return;
      if (r.status) e.status = r.status;
      if (Array.isArray(r.languages)) e.languages = r.languages.slice();
      if (typeof r.sbom_components === "number") e.components = r.sbom_components;
      if (typeof r.findings_total === "number") e.findings = r.findings_total;
      if (typeof r.vuln_total === "number") e.vulnerabilities = r.vuln_total;
    });
    (ds.repository_risk || []).forEach(function (r) {
      var e = ensure(r.repo); if (!e) return;
      if (r.status) e.status = r.status;
      if (Array.isArray(r.languages) && r.languages.length) e.languages = r.languages.slice();
      if (typeof r.components === "number") e.components = r.components;
      if (typeof r.findings === "number") e.findings = r.findings;
      if (typeof r.vulnerabilities === "number") e.vulnerabilities = r.vulnerabilities;
    });
    (ds.repository_distribution || []).forEach(function (r) {
      var e = ensure(r.repo); if (!e) return;
      if (r.status) e.status = r.status;
      if (typeof r.components === "number") e.components = r.components;
      if (typeof r.findings === "number") e.findings = r.findings;
      if (typeof r.vulnerabilities === "number") e.vulnerabilities = r.vulnerabilities;
    });
    (ds.vulnerabilities || []).forEach(function (v) { ensure(v.repo); });
    (ds.findings || []).forEach(function (f) { ensure(f.repo); });

    return order.map(function (name) { return map[name]; }).sort(byRepo);
  }

  function allPackageTypes(doc) {
    var ds = doc.datasets || {};
    var set = {};
    (ds.vulnerabilities || []).forEach(function (v) {
      set[String(v.type == null || v.type === "" ? "unknown" : v.type)] = true;
    });
    var rel = ds.relations || {};
    (rel.severity_by_package_type || []).forEach(function (r) {
      set[String(r.type == null || r.type === "" ? "unknown" : r.type)] = true;
    });
    return Object.keys(set).sort();
  }

  function allLanguages(doc) {
    var ds = doc.datasets || {};
    var set = {};
    (ds.repositories || []).forEach(function (r) {
      (r.languages || []).forEach(function (l) { if (l) set[String(l)] = true; });
    });
    (ds.repository_risk || []).forEach(function (r) {
      (r.languages || []).forEach(function (l) { if (l) set[String(l)] = true; });
    });
    var rel = ds.relations || {};
    (rel.severity_by_language || []).forEach(function (r) { if (r.language) set[String(r.language)] = true; });
    (rel.findings_by_language || []).forEach(function (r) { if (r.language) set[String(r.language)] = true; });
    return Object.keys(set).sort();
  }

  // ¿Hay algún filtro de severidad desmarcado?
  function severityFilterActive(f) {
    for (var i = 0; i < SEVERITIES.length; i++) {
      if (f.severities[SEVERITIES[i]] === false) return true;
    }
    return false;
  }

  // Filtra el CONJUNTO DE REPOSITORIOS de las vistas por repositorio.
  // No recalcula métricas: solo decide qué repos entran en la vista.
  // Un repo coincide si tiene al menos una vulnerabilidad que cumpla los
  // filtros de severidad y tipo (según datasets.vulnerabilities) y, para
  // lenguaje, si el lenguaje está declarado en el repositorio.
  function filterScope(repos, f, vulnDetail, hasVulnDetail) {
    var query = f.repoQuery.toLowerCase();
    var needsDetail = hasVulnDetail && (severityFilterActive(f) || f.packageType !== "all");
    var byRepo = null;
    if (needsDetail) {
      byRepo = {};
      vulnDetail.forEach(function (v) {
        if (!byRepo[v.repo]) byRepo[v.repo] = [];
        byRepo[v.repo].push(v);
      });
    }
    return repos.filter(function (repo) {
      if (query && String(repo.repo).toLowerCase().indexOf(query) < 0) return false;
      if (f.language !== "all" && (repo.languages || []).indexOf(f.language) < 0) return false;
      if (needsDetail) {
        var rows = byRepo[repo.repo];
        if (!rows) return false;
        for (var i = 0; i < rows.length; i++) {
          var v = rows[i];
          if (f.severities[canonical(v.severity)] === false) continue;
          var type = String(v.type == null || v.type === "" ? "unknown" : v.type);
          if (f.packageType !== "all" && type !== f.packageType) continue;
          return true;
        }
        return false;
      }
      return true;
    });
  }

  // ---------------------------------------------------------------------------
  // Construcción de la vista
  // ---------------------------------------------------------------------------
  // Regla de oro: el tablero NO recalcula métricas derivadas. Toda métrica
  // agregada (score, severity_weighted_average, severity_median, Pearson, HHI,
  // fixed_version_share, vulns_per_component, mean_repository_score, …) se
  // muestra tal cual viene del documento del Analyzer. Los filtros solo acotan
  // el conjunto de repositorios de las vistas por repositorio.

  function normalizeRiskRow(r) {
    return {
      repo: r.repo,
      status: r.status || "",
      languages: Array.isArray(r.languages) ? r.languages : [],
      vulnerabilities: num(r.vulnerabilities),
      findings: num(r.findings),
      components: num(r.components),
      critical: num(r.critical),
      high: num(r.high),
      worst_severity: canonical(r.worst_severity),
      severity_weighted_average: r.severity_weighted_average == null ? null : num(r.severity_weighted_average),
      severity_median: r.severity_median == null ? null : num(r.severity_median),
      score: r.score == null ? null : num(r.score),
      vulns_per_component: r.vulns_per_component == null ? null : num(r.vulns_per_component),
      findings_per_component: r.findings_per_component == null ? null : num(r.findings_per_component),
      fixed_version_share: r.fixed_version_share == null ? null : num(r.fixed_version_share)
    };
  }

  function compareRiskRows(a, b) {
    var as = a.score == null ? -Infinity : a.score;
    var bs = b.score == null ? -Infinity : b.score;
    if (bs !== as) return bs - as;
    var aa = a.severity_weighted_average == null ? -Infinity : a.severity_weighted_average;
    var ba = b.severity_weighted_average == null ? -Infinity : b.severity_weighted_average;
    if (ba !== aa) return ba - aa;
    return byRepo(a, b);
  }

  // Filas por repositorio tal cual vienen del Analyzer (repository_risk).
  // Fallback: si falta, se derivan solo los campos base de repository_distribution
  // sin inventar métricas (score/medias quedan a null).
  function riskRowsFromDoc(ds) {
    var rows = (ds.repository_risk || []).map(normalizeRiskRow);
    if (!rows.length && (ds.repository_distribution || []).length) {
      rows = ds.repository_distribution.map(function (r) {
        return normalizeRiskRow({
          repo: r.repo,
          status: r.status,
          vulnerabilities: r.vulnerabilities,
          findings: r.findings,
          components: r.components,
          worst_severity: "Unknown"
        });
      });
    }
    return rows;
  }

  // Construye la vista sin recalcular nada: indicadores globales precalculados
  // y filas por repositorio del Analyzer acotadas al conjunto filtrado.
  function buildView(doc, filters) {
    var ds = doc.datasets || {};
    var meta = doc.meta || {};
    var cov = doc.coverage || {};
    var info = collectRepos(doc);
    var vulnDetail = Array.isArray(ds.vulnerabilities) ? ds.vulnerabilities : [];
    var findDetail = Array.isArray(ds.findings) ? ds.findings : [];
    var hasVulnDetail = vulnDetail.length > 0;

    var scope = filterScope(info, filters, vulnDetail, hasVulnDetail);
    var scopeMap = {};
    scope.forEach(function (r) { scopeMap[r.repo] = true; });

    // --- Indicadores globales: SIEMPRE precalculados por el Analyzer ---
    var counts = emptySeverityMap();
    (ds.severity_distribution || []).forEach(function (r) {
      if (counts.hasOwnProperty(r.severity)) counts[r.severity] = num(r.count);
    });
    var sevTotal = 0;
    SEVERITIES.forEach(function (s) { sevTotal += counts[s]; });
    var rs = ds.risk_summary || {};
    var hotspots = Array.isArray(rs.critical_hotspots) ? rs.critical_hotspots.filter(Boolean) : [];
    var rel = ds.relations || {};
    var cvs = rel.components_vs_vulnerabilities || {};

    // --- Vistas por repositorio: filas del Analyzer acotadas al alcance ---
    var riskRows = riskRowsFromDoc(ds).filter(function (r) { return !!scopeMap[r.repo]; });
    riskRows.sort(compareRiskRows);

    var view = {
      filtersActive: filtersActive(filters),
      scopeCount: scope.length,
      totalRepos: info.length,
      canFilterDetail: hasVulnDetail,
      kpi: {
        repositories: meta.repositories == null ? info.length : num(meta.repositories),
        vulnerabilities: rs.total_vulnerabilities == null ? sevTotal : num(rs.total_vulnerabilities),
        critical: counts.Critical,
        high: counts.High,
        score: rs.score == null ? null : num(rs.score),
        coverage: cov.coverage_ratio == null ? null : num(cov.coverage_ratio),
        hotspots: hotspots.length
      },
      severityCounts: counts,
      severityTotal: sevTotal,
      riskRows: riskRows,
      riskSummary: rs,
      concentration: ds.concentration || {},
      relations: {
        pearson: cvs.pearson == null ? null : num(cvs.pearson),
        pearsonN: cvs.n == null ? info.length : num(cvs.n),
        fixedVersionShare: rel.fixed_version_available_share == null ? null : num(rel.fixed_version_available_share),
        severityByPackageType: rel.severity_by_package_type || [],
        findingsByLanguage: rel.findings_by_language || [],
        severityByLanguage: rel.severity_by_language || []
      },
      topPackages: ds.top_packages || [],
      topCves: ds.top_cves || [],
      topRules: ds.top_rules || [],
      detailVulns: vulnDetail,
      detailFindings: findDetail,
      hasVulnDetail: hasVulnDetail,
      hasFindingDetail: findDetail.length > 0,
      repoNames: {}
    };
    scope.forEach(function (r) { view.repoNames[r.repo] = true; });
    return view;
  }

  // ---------------------------------------------------------------------------
  // Ordenación de la tabla de riesgo
  // ---------------------------------------------------------------------------

  function colType(key) {
    for (var i = 0; i < COLS.length; i++) if (COLS[i].key === key) return COLS[i].type;
    return "text";
  }

  function sortRows(rows, key, dir) {
    var type = colType(key);
    var sign = dir === "asc" ? 1 : -1;
    return rows.slice().sort(function (a, b) {
      var av = a[key], bv = b[key];
      var an = av == null, bn = bv == null;
      if (an && bn) return byRepo(a, b);
      if (an) return 1;
      if (bn) return -1;
      var c;
      if (type === "num") c = num(av) - num(bv);
      else if (type === "sev") c = sevIndex(av) - sevIndex(bv);
      else c = String(av) < String(bv) ? -1 : String(av) > String(bv) ? 1 : 0;
      if (c !== 0) return sign * c;
      return byRepo(a, b);
    });
  }

  function toggleSort(key) {
    if (state.sort.key === key) {
      state.sort.dir = state.sort.dir === "asc" ? "desc" : "asc";
    } else {
      state.sort.key = key;
      var type = colType(key);
      state.sort.dir = (type === "text" || type === "sev") ? "asc" : "desc";
    }
    update();
  }

  // ---------------------------------------------------------------------------
  // Tooltips
  // ---------------------------------------------------------------------------

  function initTooltip() {
    var tip = el("div", { id: "vis-tooltip", class: "tooltip", role: "tooltip", "aria-hidden": "true" });
    document.body.appendChild(tip);
    state.tipEl = tip;

    var app = document.getElementById("app");
    if (app) {
      app.addEventListener("mouseover", function (e) { showTipFor(e.target); });
      app.addEventListener("mouseout", function (e) {
        var t = closestTip(e.target);
        if (t && t === state.tipTarget && !containsNode(t, e.relatedTarget)) hideTip();
      });
      app.addEventListener("focusin", function (e) { showTipFor(e.target); });
      app.addEventListener("focusout", function (e) {
        var t = closestTip(e.target);
        if (t && t === state.tipTarget && !containsNode(t, e.relatedTarget)) hideTip();
      });
    }
    window.addEventListener("scroll", hideTip, true);
    window.addEventListener("resize", hideTip);
  }

  function closestTip(node) {
    while (node && node !== document) {
      if (node.getAttribute && node.getAttribute("data-tip")) return node;
      node = node.parentNode;
    }
    return null;
  }

  function containsNode(parent, child) {
    if (!parent || !child) return false;
    return parent === child || (parent.contains ? parent.contains(child) : false);
  }

  function showTipFor(target) {
    var node = closestTip(target);
    if (!node) return;
    var text = node.getAttribute("data-tip");
    if (!text) return;
    state.tipTarget = node;
    state.tipEl.textContent = text;
    state.tipEl.setAttribute("aria-hidden", "false");
    state.tipEl.classList.add("visible");
    positionTip(node);
  }

  function positionTip(node) {
    var rect = node.getBoundingClientRect();
    var tip = state.tipEl;
    var tw = tip.offsetWidth || 160;
    var th = tip.offsetHeight || 30;
    var left = rect.left + rect.width / 2 - tw / 2;
    var top = rect.top - th - 8;
    if (top < 4) top = rect.bottom + 8;
    left = Math.max(4, Math.min(left, window.innerWidth - tw - 4));
    top = Math.max(4, Math.min(top, window.innerHeight - th - 4));
    tip.style.left = left + "px";
    tip.style.top = top + "px";
  }

  function hideTip() {
    if (!state.tipEl) return;
    state.tipEl.classList.remove("visible");
    state.tipEl.setAttribute("aria-hidden", "true");
    state.tipTarget = null;
  }

  // ---------------------------------------------------------------------------
  // Cabecera, barra de filtros y secciones estáticas
  // ---------------------------------------------------------------------------

  function renderHeader(doc) {
    var meta = doc.meta || {};
    var header = el("header", { class: "app-header card" });
    header.appendChild(el("h1", { text: "Visualizer · " + (meta.organization || "organización") }));

    var line = el("div", { class: "meta-line" });
    if (meta.source_kind) line.appendChild(el("span", { class: "kind-badge", text: String(meta.source_kind) }));
    line.appendChild(el("span", { text: "Origen: " + (meta.source || "—") }));
    line.appendChild(el("span", { text: "Generado: " + (meta.generated_at || "—") }));
    line.appendChild(el("span", { text: "Esquema: " + (doc.schema_version || "—") }));
    var repoTotal = meta.repositories != null
      ? meta.repositories
      : ((doc.datasets && doc.datasets.repositories) ? doc.datasets.repositories.length : 0);
    line.appendChild(el("span", { text: "Repositorios: " + fmtInt(repoTotal) }));
    header.appendChild(line);

    var warnings = (meta.warnings || []).filter(function (w) { return w != null && String(w).length; });
    if (warnings.length) {
      var box = el("div", { class: "warnbox", role: "status" }, [
        el("strong", { text: "Avisos (" + warnings.length + ")" })
      ]);
      var list = el("ul");
      warnings.forEach(function (w) { list.appendChild(el("li", { text: String(w) })); });
      box.appendChild(list);
      header.appendChild(box);
    }
    return header;
  }

  function renderToolbar(doc) {
    var hasDetail = Array.isArray((doc.datasets || {}).vulnerabilities)
      && doc.datasets.vulnerabilities.length > 0;
    var toolbar = el("div", { class: "toolbar", role: "group", "aria-label": "Filtros del tablero" });
    var row = el("div", { class: "toolbar-row" });

    // Búsqueda por repositorio
    var searchField = el("div", { class: "field" });
    searchField.appendChild(el("label", { for: "f-repo", text: "Repositorio" }));
    var input = el("input", { type: "search", id: "f-repo", placeholder: "Buscar repositorio…", "aria-label": "Buscar repositorio" });
    input.value = state.filters.repoQuery;
    searchField.appendChild(input);
    row.appendChild(searchField);

    // Severidades
    var sevField = el("div", { class: "field", role: "group", "aria-label": "Filtrar por severidad" });
    sevField.appendChild(el("span", { class: "field-label", text: "Severidad" }));
    var checks = el("div", { class: "sev-checks" });
    SEVERITIES.forEach(function (s) {
      var id = "sev-" + s.toLowerCase();
      var lab = el("label", { class: "sev-check", for: id });
      var cb = el("input", { type: "checkbox", id: id, checked: state.filters.severities[s] !== false, disabled: !hasDetail });
      cb.setAttribute("data-sev", s);
      lab.appendChild(cb);
      lab.appendChild(el("span", { class: "swatch " + sevClass(s), "aria-hidden": "true" }));
      lab.appendChild(el("span", { text: s }));
      checks.appendChild(lab);
    });
    sevField.appendChild(checks);
    row.appendChild(sevField);

    // Tipo de paquete
    var ptField = el("div", { class: "field" });
    ptField.appendChild(el("label", { for: "f-type", text: "Tipo de paquete" }));
    var ptSelect = el("select", { id: "f-type", "aria-label": "Filtrar por tipo de paquete", disabled: !hasDetail });
    ptSelect.appendChild(el("option", { value: "all", text: "Todos" }));
    allPackageTypes(doc).forEach(function (x) { ptSelect.appendChild(el("option", { value: x, text: x })); });
    ptSelect.value = state.filters.packageType;
    ptField.appendChild(ptSelect);
    row.appendChild(ptField);

    // Lenguaje
    var lgField = el("div", { class: "field" });
    lgField.appendChild(el("label", { for: "f-lang", text: "Lenguaje" }));
    var lgSelect = el("select", { id: "f-lang", "aria-label": "Filtrar por lenguaje" });
    lgSelect.appendChild(el("option", { value: "all", text: "Todos" }));
    allLanguages(doc).forEach(function (x) { lgSelect.appendChild(el("option", { value: x, text: x })); });
    lgSelect.value = state.filters.language;
    lgField.appendChild(lgSelect);
    row.appendChild(lgField);

    // Botón de reinicio
    var resetField = el("div", { class: "field" });
    resetField.appendChild(el("span", { class: "field-label", "aria-hidden": "true", text: "\u00a0" }));
    var reset = el("button", { type: "button", class: "btn", text: "Restablecer" });
    resetField.appendChild(reset);
    row.appendChild(resetField);

    toolbar.appendChild(row);
    if (!hasDetail) {
      toolbar.appendChild(el("p", {
        class: "note",
        text: "El documento no incluye detalle de vulnerabilidades: los filtros de severidad y tipo de paquete están deshabilitados. No se recalcula ninguna métrica."
      }));
    }
    state.statusEl = el("span", { class: "sr-only", role: "status", "aria-live": "polite" });
    toolbar.appendChild(state.statusEl);

    input.addEventListener("input", function () {
      state.filters.repoQuery = input.value;
      scheduleUpdate();
    });
    checks.addEventListener("change", function (e) {
      var s = e.target.getAttribute("data-sev");
      if (!s) return;
      state.filters.severities[s] = e.target.checked;
      update();
    });
    ptSelect.addEventListener("change", function () { state.filters.packageType = ptSelect.value; update(); });
    lgSelect.addEventListener("change", function () { state.filters.language = lgSelect.value; update(); });
    reset.addEventListener("click", function () {
      state.filters = defaultFilters();
      input.value = "";
      ptSelect.value = "all";
      lgSelect.value = "all";
      var boxes = checks.querySelectorAll("input[data-sev]");
      for (var i = 0; i < boxes.length; i++) boxes[i].checked = true;
      update();
      input.focus();
    });

    return toolbar;
  }

  function renderObservations(doc) {
    var card = el("section", { class: "card" });
    card.appendChild(el("div", { class: "card-head" }, [el("h2", { text: "Observaciones" })]));
    var observations = doc.observations || [];
    if (!observations.length) { card.appendChild(sinDatos()); return card; }

    var list = el("div", { class: "obs" });
    observations.forEach(function (obs) {
      var item = el("div", { class: "obs-item" });
      var head = el("div", { class: "obs-head" });
      head.appendChild(el("span", { class: "obs-id", text: String(obs.id || "—") }));
      head.appendChild(el("span", { class: "obs-title", text: String(obs.title || "") }));
      if (obs.metric) head.appendChild(el("span", { class: "obs-metric mono", text: String(obs.metric) }));
      item.appendChild(head);
      if (obs.statement) item.appendChild(el("p", { text: String(obs.statement) }));
      if (obs.evidence != null) {
        var details = el("details");
        details.appendChild(el("summary", { text: "Evidencia" }));
        var pre = el("pre");
        pre.textContent = prettyJson(obs.evidence);
        details.appendChild(pre);
        item.appendChild(details);
      }
      list.appendChild(item);
    });
    card.appendChild(list);
    return card;
  }

  function prettyJson(value) {
    try { return JSON.stringify(value, null, 2); } catch (e) { return String(value); }
  }

  function renderLimitations(doc) {
    var card = el("section", { class: "card" });
    card.appendChild(el("div", { class: "card-head" }, [el("h2", { text: "Limitaciones" })]));
    var limits = doc.limitations || [];
    if (!limits.length) { card.appendChild(sinDatos()); return card; }
    var list = el("ul", { class: "limits" });
    limits.forEach(function (text) { list.appendChild(el("li", { text: String(text) })); });
    card.appendChild(list);
    return card;
  }

  // ---------------------------------------------------------------------------
  // Tarjetas dinámicas
  // ---------------------------------------------------------------------------

  function renderKpiCard(view) {
    var card = el("section", { class: "card" });
    card.appendChild(el("div", { class: "card-head" }, [
      el("h2", { text: "Indicadores" }),
      el("span", { class: "sub", text: "Globales · sin filtrar (Analyzer)" })
    ]));
    var grid = el("div", { class: "kpis" });
    grid.appendChild(kpiItem("Repositorios", fmtInt(view.kpi.repositories), "En el alcance de los filtros"));
    grid.appendChild(kpiItem("Vulnerabilidades", fmtInt(view.kpi.vulnerabilities), null));
    grid.appendChild(kpiItem("Critical", fmtInt(view.kpi.critical), null, "sev-critical"));
    grid.appendChild(kpiItem("High", fmtInt(view.kpi.high), null, "sev-high"));
    grid.appendChild(kpiItem("Nota global", (view.kpi.score == null ? "—" : fmt1(view.kpi.score)) + " / 10", "Gravedad media ponderada", scoreClass(view.kpi.score)));
    grid.appendChild(kpiItem("Cobertura", fmtPctOrDash(view.kpi.coverage), "Al menos una dimensión con éxito", covClass(view.kpi.coverage)));
    grid.appendChild(kpiItem("Hotspots Critical", fmtInt(view.kpi.hotspots), "Repos con ≥1 Critical", view.kpi.hotspots > 0 ? "sev-critical" : "ok"));
    card.appendChild(grid);
    return card;
  }

  function kpiItem(label, value, hint, cls) {
    var node = el("div", { class: "kpi" + (cls ? " " + cls : "") });
    node.appendChild(el("div", { class: "value", text: value }));
    node.appendChild(el("div", { class: "label", text: label }));
    if (hint) node.appendChild(el("div", { class: "hint", text: hint }));
    return node;
  }

  function scoreClass(score) {
    if (score == null) return "";
    if (score >= 7) return "sev-critical";
    if (score >= 4) return "warn";
    return "ok";
  }

  function covClass(ratio) {
    if (ratio == null) return "";
    if (ratio >= 0.999) return "ok";
    if (ratio >= 0.75) return "warn";
    return "sev-high";
  }

  function renderSeverityCard(view) {
    var card = el("section", { class: "card" });
    card.appendChild(el("div", { class: "card-head" }, [
      el("h2", { text: "Distribución de severidad" }),
      el("span", { class: "sub", text: fmtInt(view.severityTotal) + " vulnerabilidades" })
    ]));
    var total = view.severityTotal;
    if (!total) { card.appendChild(sinDatos()); return card; }

    var wrap = el("div", { class: "donut-wrap" });
    var size = 200, r = 72, cx = 100, cy = 100, stroke = 24;
    var circumference = 2 * Math.PI * r;
    var svg = svgEl("svg", {
      class: "donut", viewBox: "0 0 " + size + " " + size, role: "group",
      "aria-label": "Dona de distribución global de severidad"
    });
    svg.appendChild(svgEl("title", { text: "Distribución global de severidad de las vulnerabilidades" }));
    var offset = 0;
    SEVERITIES.forEach(function (s) {
      var count = view.severityCounts[s] || 0;
      if (!count) return;
      var frac = count / total;
      var len = frac * circumference;
      var circle = svgEl("circle", {
        cx: cx, cy: cy, r: r, fill: "none", "stroke-width": stroke,
        "stroke-dasharray": len + " " + (circumference - len),
        "stroke-dashoffset": String(-offset),
        transform: "rotate(-90 " + cx + " " + cy + ")", tabindex: "0"
      });
      circle.style.stroke = sevColorVar(s);
      var tip = s + ": " + count + " (" + pct(frac) + ")";
      circle.setAttribute("data-tip", tip);
      circle.setAttribute("aria-label", tip);
      svg.appendChild(circle);
      offset += len;
    });
    svg.appendChild(svgEl("text", { class: "donut-total", x: cx, y: cy + 2, "text-anchor": "middle", text: String(total) }));
    svg.appendChild(svgEl("text", { class: "donut-sub", x: cx, y: cy + 20, "text-anchor": "middle", text: "vulnerabilidades" }));
    wrap.appendChild(svg);

    var legend = el("ul", { class: "legend" });
    SEVERITIES.forEach(function (s) {
      var count = view.severityCounts[s] || 0;
      var li = el("li");
      li.appendChild(el("span", { class: "swatch " + sevClass(s), "aria-hidden": "true" }));
      li.appendChild(el("span", { class: "legend-name", text: s }));
      li.appendChild(el("span", { class: "legend-val", text: fmtInt(count) + " · " + pct(total ? count / total : 0) }));
      legend.appendChild(li);
    });
    wrap.appendChild(legend);
    card.appendChild(wrap);
    return card;
  }

  function renderRiskCard(view) {
    var card = el("section", { class: "card" });
    card.appendChild(el("div", { class: "card-head" }, [
      el("h2", { text: "Riesgo por repositorio" }),
      el("span", { class: "sub", text: "Clic en el encabezado para ordenar; clic en el nombre para ver el detalle." })
    ]));
    if (!view.riskRows.length) { card.appendChild(sinDatos()); return card; }

    var wrap = el("div", { class: "table-wrap" });
    var table = el("table", { class: "data" });
    table.appendChild(el("caption", { class: "sr-only", text: "Riesgo por repositorio, ordenable por columnas" }));

    var thead = el("thead");
    var headRow = el("tr");
    COLS.forEach(function (col) {
      var th = el("th", { scope: "col" });
      th.setAttribute("class", "sortable" + (col.type === "num" ? " num" : ""));
      var active = state.sort.key === col.key;
      th.setAttribute("aria-sort", active ? (state.sort.dir === "asc" ? "ascending" : "descending") : "none");
      var button = el("button", { type: "button", "data-focus-id": "sort:" + col.key, "aria-label": "Ordenar por " + col.label });
      button.appendChild(el("span", { text: col.label }));
      button.appendChild(el("span", { class: "sort-arrow", "aria-hidden": "true" }));
      (function (key) {
        button.addEventListener("click", function () { toggleSort(key); });
      })(col.key);
      th.appendChild(button);
      headRow.appendChild(th);
    });
    thead.appendChild(headRow);
    table.appendChild(thead);

    var rows = sortRows(view.riskRows, state.sort.key, state.sort.dir);
    var tbody = el("tbody");
    rows.forEach(function (r) {
      var tr = el("tr", { "data-repo": r.repo });
      if (state.selectedRepo === r.repo) tr.setAttribute("class", "selected");

      var tdRepo = el("td");
      var repoBtn = el("button", { type: "button", class: "btn link", "data-focus-id": "repo:" + r.repo, text: r.repo, "aria-label": "Ver detalle de " + r.repo });
      (function (name) {
        repoBtn.addEventListener("click", function () { selectRepo(name); });
      })(r.repo);
      tdRepo.appendChild(repoBtn);
      tr.appendChild(tdRepo);

      tr.appendChild(el("td", {}, [el("span", { class: "badge status", text: r.status || "—" })]));

      var tdScore = el("td");
      var scoreCell = el("div", { class: "score-cell" });
      var scoreBar = el("div", { class: "score-bar" });
      var scoreFill = el("span");
      var sc = r.score == null ? 0 : r.score;
      scoreFill.style.width = Math.max(0, Math.min(100, sc / 10 * 100)) + "%";
      scoreFill.style.background = sevColorVar(r.worst_severity);
      scoreBar.appendChild(scoreFill);
      scoreCell.appendChild(scoreBar);
      scoreCell.appendChild(el("span", { class: "score-num", text: r.score == null ? "—" : fmt1(r.score) }));
      tdScore.appendChild(scoreCell);
      tr.appendChild(tdScore);

      tr.appendChild(el("td", { class: "num", text: fmt2OrDash(r.severity_weighted_average) }));
      tr.appendChild(el("td", { class: "num", text: fmt2OrDash(r.severity_median) }));
      tr.appendChild(el("td", {}, [sevBadge(r.worst_severity)]));
      tr.appendChild(el("td", { class: "num", text: fmtInt(r.critical) }));
      tr.appendChild(el("td", { class: "num", text: fmtInt(r.high) }));
      tr.appendChild(el("td", { class: "num", text: fmtInt(r.vulnerabilities) }));
      tr.appendChild(el("td", { class: "num", text: fmtInt(r.findings) }));
      tr.appendChild(el("td", { class: "num", text: fmtInt(r.components) }));
      tr.appendChild(el("td", { class: "num", text: fmt2OrDash(r.vulns_per_component) }));
      tr.appendChild(el("td", { class: "num", text: fmt2OrDash(r.findings_per_component) }));
      tr.appendChild(el("td", { class: "num", text: fmtPctOrDash(r.fixed_version_share) }));
      tbody.appendChild(tr);
    });
    table.appendChild(tbody);
    wrap.appendChild(table);
    card.appendChild(wrap);
    return card;
  }

  function renderVulnsByRepoCard(view) {
    var card = el("section", { class: "card" });
    card.appendChild(el("div", { class: "card-head" }, [
      el("h2", { text: "Vulnerabilidades por repositorio" }),
      el("span", { class: "sub", text: "Color por peor severidad" })
    ]));
    var rows = view.riskRows.filter(function (r) { return r.vulnerabilities > 0; })
      .slice().sort(function (a, b) {
        if (b.vulnerabilities !== a.vulnerabilities) return b.vulnerabilities - a.vulnerabilities;
        return byRepo(a, b);
      });
    if (!rows.length) { card.appendChild(sinDatos()); return card; }

    var limit = 25;
    var shown = rows.slice(0, limit);
    var max = shown[0].vulnerabilities;
    var list = el("ul", { class: "bars" });
    shown.forEach(function (r) {
      var worst = canonical(r.worst_severity);
      var li = el("li", {
        class: "bar-row",
        "data-tip": r.repo + ": " + r.vulnerabilities + " vulnerabilidades, peor " + worst,
        "aria-label": r.repo + ": " + r.vulnerabilities + " vulnerabilidades, peor " + worst
      });
      li.appendChild(el("span", { class: "bar-label", text: r.repo, title: r.repo }));
      var track = el("span", { class: "bar-track" });
      var fill = el("span", { class: "bar-fill" });
      fill.style.width = (max > 0 ? Math.max(1.5, r.vulnerabilities / max * 100) : 0) + "%";
      fill.style.background = sevColorVar(worst);
      track.appendChild(fill);
      li.appendChild(track);
      li.appendChild(el("span", { class: "bar-value", text: fmtInt(r.vulnerabilities) }));
      list.appendChild(li);
    });
    card.appendChild(list);
    if (rows.length > limit) {
      card.appendChild(el("p", { class: "note", text: "Mostrando " + limit + " de " + rows.length + " repositorios con vulnerabilidades." }));
    }
    return card;
  }

  function renderScatterCard(view) {
    var card = el("section", { class: "card" });
    var pear = view.relations.pearson;
    var sub = el("span", {
      class: "sub",
      text: pear == null ? "Pearson global: no calculable" : "Pearson global (Analyzer) r = " + fmt4(pear) + " (n=" + fmtInt(view.relations.pearsonN) + ")"
    });
    var toggleId = "scatter-density";
    var lab = el("label", { class: "sev-check", for: toggleId });
    var cb = el("input", { type: "checkbox", id: toggleId, "data-focus-id": "density", checked: !!state.scatterDensity });
    cb.addEventListener("change", function () { state.scatterDensity = cb.checked; update(); });
    lab.appendChild(cb);
    lab.appendChild(el("span", { text: "Ver densidad" }));
    card.appendChild(el("div", { class: "card-head" }, [
      el("h2", { text: "Componentes vs vulnerabilidades" }),
      el("div", { class: "toolbar-row" }, [sub, lab])
    ]));

    var points = view.riskRows.map(function (r) {
      return {
        repo: r.repo,
        components: num(r.components),
        vulnerabilities: num(r.vulnerabilities),
        findings: num(r.findings),
        worst_severity: canonical(r.worst_severity)
      };
    });
    if (!points.length) { card.appendChild(sinDatos()); return card; }

    var W = 640, H = 360, M = { l: 52, r: 18, t: 16, b: 44 };
    var pw = W - M.l - M.r, ph = H - M.t - M.b;
    var maxX = 0, maxY = 0, maxF = 0;
    points.forEach(function (p) {
      if (p.components > maxX) maxX = p.components;
      if (p.vulnerabilities > maxY) maxY = p.vulnerabilities;
      if (p.findings > maxF) maxF = p.findings;
    });
    if (maxX <= 0) maxX = 1;
    if (maxY <= 0) maxY = 1;

    var svg = svgEl("svg", {
      class: "scatter", viewBox: "0 0 " + W + " " + H, role: "group",
      "aria-label": "Dispersión de " + points.length + " repositorios: componentes del SBOM frente a vulnerabilidades"
        + (pear == null ? "" : "; correlación de Pearson " + fmt4(pear))
    });
    svg.appendChild(svgEl("title", { text: "Dispersión de componentes del SBOM frente a vulnerabilidades" }));

    var i, t, vx, vy;
    for (i = 0; i <= 4; i++) {
      t = i / 4;
      vy = M.t + ph - t * ph;
      svg.appendChild(svgEl("line", { class: "gridline", x1: M.l, y1: vy, x2: M.l + pw, y2: vy }));
      svg.appendChild(svgEl("text", { class: "tick", x: M.l - 6, y: vy + 3, "text-anchor": "end", text: String(Math.round(t * maxY)) }));
      vx = M.l + t * pw;
      svg.appendChild(svgEl("line", { class: "gridline", x1: vx, y1: M.t, x2: vx, y2: M.t + ph }));
      svg.appendChild(svgEl("text", { class: "tick", x: vx, y: M.t + ph + 14, "text-anchor": "middle", text: String(Math.round(t * maxX)) }));
    }
    svg.appendChild(svgEl("line", { class: "axis", x1: M.l, y1: M.t, x2: M.l, y2: M.t + ph }));
    svg.appendChild(svgEl("line", { class: "axis", x1: M.l, y1: M.t + ph, x2: M.l + pw, y2: M.t + ph }));
    svg.appendChild(svgEl("text", { class: "axis-title", x: M.l + pw / 2, y: H - 4, "text-anchor": "middle", text: "Componentes del SBOM" }));
    svg.appendChild(svgEl("text", {
      class: "axis-title", x: 14, y: M.t + ph / 2, "text-anchor": "middle",
      transform: "rotate(-90 14 " + (M.t + ph / 2) + ")", text: "Vulnerabilidades"
    }));

    if (state.scatterDensity) {
      var cols = 8, rowsGrid = 6, grid = [];
      for (i = 0; i < cols * rowsGrid; i++) grid.push(0);
      points.forEach(function (p) {
        var gx = Math.min(cols - 1, Math.floor(p.components / maxX * cols));
        var gy = Math.min(rowsGrid - 1, Math.floor(p.vulnerabilities / maxY * rowsGrid));
        grid[gy * cols + gx]++;
      });
      var maxCell = 0;
      grid.forEach(function (c) { if (c > maxCell) maxCell = c; });
      var cw = pw / cols, ch = ph / rowsGrid;
      for (var gy2 = 0; gy2 < rowsGrid; gy2++) {
        for (var gx2 = 0; gx2 < cols; gx2++) {
          var cellCount = grid[gy2 * cols + gx2];
          if (!cellCount) continue;
          var rect = svgEl("rect", {
            class: "cell", x: M.l + gx2 * cw, y: M.t + (rowsGrid - 1 - gy2) * ch,
            width: cw, height: ch, rx: 2
          });
          rect.style.fill = "var(--accent)";
          rect.style.opacity = String(0.12 + 0.7 * (cellCount / maxCell));
          rect.setAttribute("data-tip", "Densidad: " + cellCount + " repositorio(s) en esta celda");
          svg.appendChild(rect);
        }
      }
    }

    points.forEach(function (p) {
      var px = M.l + (p.components / maxX) * pw;
      var py = M.t + ph - (p.vulnerabilities / maxY) * ph;
      var radius = maxF > 0 ? 4 + 7 * Math.sqrt(p.findings / maxF) : 5;
      var circle = svgEl("circle", { class: "pt", cx: px, cy: py, r: radius, tabindex: "0" });
      circle.style.fill = sevColorVar(p.worst_severity);
      var tip = p.repo + ": " + p.components + " componentes, " + p.vulnerabilities + " vulnerabilidades, "
        + p.findings + " hallazgos, peor " + p.worst_severity;
      circle.setAttribute("data-tip", tip);
      circle.setAttribute("aria-label", tip);
      svg.appendChild(circle);
    });

    card.appendChild(el("div", { class: "scatter-wrap" }, [svg]));
    card.appendChild(el("p", { class: "scatter-note", text: "Tamaño de burbuja: hallazgos CodeQL. Color: peor severidad del repositorio. El coeficiente de Pearson es global (Analyzer); los puntos se acotan a los filtros. Correlación ≠ causalidad." }));
    if (state.scatterDensity) {
      card.appendChild(el("p", { class: "scatter-note", text: "La rejilla muestra el número de repositorios por celda (densidad)." }));
    }
    return card;
  }

  function barCard(title, sub, items, note) {
    var card = el("section", { class: "card" });
    var head = el("div", { class: "card-head" }, [el("h2", { text: title })]);
    if (sub) head.appendChild(el("span", { class: "sub", text: sub }));
    card.appendChild(head);
    if (!items.length) {
      card.appendChild(sinDatos());
      if (note) card.appendChild(el("p", { class: "note", text: note }));
      return card;
    }

    var max = 0;
    items.forEach(function (it) { if (it.value > max) max = it.value; });
    var list = el("ul", { class: "bars" });
    items.forEach(function (it) {
      var li = el("li", { class: "bar-row", "data-tip": it.tip, "aria-label": it.tip || it.label + ": " + it.value });
      li.appendChild(el("span", { class: "bar-label", text: it.label, title: it.label }));
      var track = el("span", { class: "bar-track" });
      var fill = el("span", { class: "bar-fill" });
      fill.style.width = (max > 0 ? Math.max(1.5, it.value / max * 100) : 0) + "%";
      fill.style.background = it.color || "var(--accent)";
      track.appendChild(fill);
      li.appendChild(track);
      li.appendChild(el("span", { class: "bar-value", text: fmtInt(it.value) }));
      list.appendChild(li);
    });
    card.appendChild(list);
    if (note) card.appendChild(el("p", { class: "note", text: note }));
    return card;
  }

  function renderTopPackagesCard(view) {
    var items = (view.topPackages || []).map(function (p) {
      var worst = canonical(p.worst_severity);
      return {
        label: String(p.package == null ? "unknown" : p.package),
        value: num(p.count),
        color: sevColorVar(worst),
        tip: p.package + ": " + num(p.count) + " vulnerabilidades en " + num(p.repos_affected) + " repositorio(s), peor " + worst
      };
    });
    return barCard("Top paquetes", "Por vulnerabilidades acumuladas", items, null);
  }

  function renderTopCvesCard(view) {
    var items = (view.topCves || []).map(function (c) {
      var sev = canonical(c.severity);
      return {
        label: String(c.id == null ? "unknown" : c.id),
        value: num(c.count),
        color: sevColorVar(sev),
        tip: c.id + " (" + sev + "): " + num(c.count) + " aparición(es) en " + num(c.repos_affected) + " repositorio(s)"
      };
    });
    return barCard("Top CVEs / GHSA", "Identificadores más repetidos", items, null);
  }

  function renderTopRulesCard(view) {
    var items = (view.topRules || []).map(function (r) {
      return {
        label: String(r.rule_id == null ? "unknown" : r.rule_id),
        value: num(r.count),
        color: "var(--accent)",
        tip: r.rule_id + ": " + num(r.count) + " hallazgo(s) en " + num(r.repos_affected) + " repositorio(s)"
      };
    });
    var note = view.hasFindingDetail ? null : "El documento no incluye hallazgos de CodeQL.";
    return barCard("Top reglas CodeQL", "Hallazgos por regla", items, note);
  }

  // Agrupa filas {clave, severity} en grupos con total y desglose por severidad.
  function groupStack(rows, keyField) {
    var map = {}, order = [];
    rows.forEach(function (r) {
      var key = String(r[keyField] == null || r[keyField] === "" ? "unknown" : r[keyField]);
      if (!map[key]) {
        var sev = {};
        SEVERITIES.forEach(function (s) { sev[s] = 0; });
        map[key] = { key: key, total: 0, sev: sev };
        order.push(key);
      }
      var s = canonical(r.severity);
      map[key].sev[s] += num(r.count);
      map[key].total += num(r.count);
    });
    return order.map(function (k) { return map[k]; }).sort(function (a, b) {
      if (b.total !== a.total) return b.total - a.total;
      return a.key < b.key ? -1 : a.key > b.key ? 1 : 0;
    });
  }

  function stackCard(title, sub, rows, keyField, note) {
    var card = el("section", { class: "card" });
    var head = el("div", { class: "card-head" }, [el("h2", { text: title })]);
    if (sub) head.appendChild(el("span", { class: "sub", text: sub }));
    card.appendChild(head);
    var groups = groupStack(rows || [], keyField);
    if (!groups.length) { card.appendChild(sinDatos()); return card; }

    var limit = 12;
    var shown = groups.slice(0, limit);
    shown.forEach(function (g) {
      var row = el("div", { class: "stack-row" });
      row.appendChild(el("span", { class: "bar-label", text: g.key, title: g.key }));
      var track = el("span", { class: "stack-track" });
      SEVERITIES.forEach(function (s) {
        var count = g.sev[s] || 0;
        if (!count) return;
        var seg = el("span", { class: "stack-seg" });
        seg.style.width = (g.total ? count / g.total * 100 : 0) + "%";
        seg.style.background = sevColorVar(s);
        seg.setAttribute("data-tip", g.key + " · " + s + ": " + count);
        track.appendChild(seg);
      });
      row.appendChild(track);
      row.appendChild(el("span", { class: "bar-value", text: fmtInt(g.total) }));
      card.appendChild(row);
    });
    if (groups.length > limit) {
      card.appendChild(el("p", { class: "note", text: "Mostrando " + limit + " de " + groups.length + " grupos." }));
    }
    if (note) card.appendChild(el("p", { class: "note", text: note }));
    return card;
  }

  function renderSevByTypeCard(view) {
    return stackCard("Severidad por tipo de paquete", "Barras apiladas por severidad", view.relations.severityByPackageType, "type", null);
  }

  function renderSevByLangCard(view) {
    var note = (view.relations.severityByLanguage && view.relations.severityByLanguage.length)
      ? "Los repos multi-lenguaje cuentan la vulnerabilidad una vez por lenguaje; los totales no suman el global."
      : null;
    return stackCard("Severidad por lenguaje", "Barras apiladas por severidad", view.relations.severityByLanguage, "language", note);
  }

  function renderContextCard(view) {
    var card = el("section", { class: "card" });
    card.appendChild(el("div", { class: "card-head" }, [el("h2", { text: "Concentración y reparabilidad" })]));
    var c = view.concentration || {};
    var rs = view.riskSummary || {};
    var rel = view.relations || {};
    var items = [
      ["Repos con vulnerabilidades", fmtIntOrDash(c.repositories_with_vulns)],
      ["Top N efectivo", fmtIntOrDash(c.top_n)],
      ["Cuota top N", fmtPctOrDash(c.top_n_share)],
      ["Cuota decil superior", fmtPctOrDash(c.top_10pct_share)],
      ["HHI", fmt4OrDash(c.hhi)],
      ["Repos puntuados", fmtIntOrDash(rs.repositories_scored)],
      ["Nota media por repo", fmt1OrDash(rs.mean_repository_score) + " / 10"],
      ["Nota máxima por repo", fmt1OrDash(rs.max_repository_score) + " / 10"],
      ["Peor severidad global", canonical(rs.worst_severity || "Unknown")],
      ["Corrección disponible", fmtPctOrDash(rel.fixedVersionShare)]
    ];
    var grid = el("div", { class: "kpis" });
    items.forEach(function (it) {
      grid.appendChild(el("div", { class: "kpi" }, [
        el("div", { class: "value", text: it[1] }),
        el("div", { class: "label", text: it[0] })
      ]));
    });
    card.appendChild(grid);
    card.appendChild(el("p", { class: "note", text: "La nota 1-10 resume gravedad media con pesos fijos (Critical=10 … Unknown=0), no volumen ni explotabilidad; la correlación no implica causalidad." }));
    return card;
  }

  // ---------------------------------------------------------------------------
  // Drill-down por repositorio
  // ---------------------------------------------------------------------------

  function renderDrilldown(view) {
    var container = state.drillEl;
    if (!container) return;
    clear(container);
    var repo = state.selectedRepo;
    if (!repo) return;

    var row = null;
    for (var i = 0; i < view.riskRows.length; i++) {
      if (view.riskRows[i].repo === repo) { row = view.riskRows[i]; break; }
    }

    var card = el("section", { class: "card drill", id: "vis-drill" });
    var head = el("div", { class: "drill-head" });
    head.appendChild(el("h2", { class: "drill-title", tabindex: "-1", text: "Detalle · " + repo }));
    var close = el("button", { type: "button", class: "btn", "data-focus-id": "drill-close", text: "Cerrar" });
    close.addEventListener("click", function () {
      state.selectedRepo = null;
      renderDrilldown(view);
      restoreRepoFocus(repo);
    });
    head.appendChild(close);
    card.appendChild(head);

    if (row) {
      var summary = el("div", { class: "drill-summary" });
      var pairs = [
        ["Estado", row.status || "—"],
        ["Lenguajes", (row.languages && row.languages.length ? row.languages.join(", ") : "—")],
        ["Componentes", fmtInt(row.components)],
        ["Nota", row.score == null ? "—" : fmt1(row.score) + " / 10"],
        ["Peor severidad", canonical(row.worst_severity)],
        ["Vulns", fmtInt(row.vulnerabilities)],
        ["Findings", fmtInt(row.findings)]
      ];
      pairs.forEach(function (p) {
        summary.appendChild(el("span", {}, [el("strong", { text: p[0] + ": " }), el("span", { text: String(p[1]) })]));
      });
      card.appendChild(summary);
    }

    var vulns = (view.detailVulns || []).filter(function (v) { return v.repo === repo; });
    var findings = (view.detailFindings || []).filter(function (f) { return f.repo === repo; });

    card.appendChild(el("h3", { text: "Vulnerabilidades (" + vulns.length + ")" }));
    card.appendChild(vulnTable(vulns));
    card.appendChild(el("h3", { text: "Hallazgos CodeQL (" + findings.length + ")" }));
    card.appendChild(findingTable(findings));
    container.appendChild(card);
  }

  function vulnTable(vulns) {
    if (!vulns.length) return sinDatos("Sin vulnerabilidades registradas.");
    var rows = vulns.slice().sort(function (a, b) {
      var c = sevIndex(a.severity) - sevIndex(b.severity);
      if (c !== 0) return c;
      return String(a.id) < String(b.id) ? -1 : String(a.id) > String(b.id) ? 1 : 0;
    });
    var table = el("table", { class: "data" });
    table.appendChild(el("caption", { class: "sr-only", text: "Vulnerabilidades del repositorio" }));
    var thead = el("thead");
    var hr = el("tr");
    ["ID", "Severidad", "Paquete", "Versión", "Tipo", "Corregida", "Namespace"].forEach(function (h) {
      hr.appendChild(el("th", { scope: "col", text: h }));
    });
    thead.appendChild(hr);
    table.appendChild(thead);
    var tbody = el("tbody");
    rows.slice(0, ROW_LIMIT).forEach(function (v) {
      var tr = el("tr");
      tr.appendChild(el("td", { class: "mono", text: String(v.id == null ? "—" : v.id) }));
      tr.appendChild(el("td", {}, [sevBadge(v.severity)]));
      tr.appendChild(el("td", { text: String(v.package == null ? "—" : v.package) }));
      tr.appendChild(el("td", { text: String(v.version == null ? "—" : v.version) }));
      tr.appendChild(el("td", { text: String(v.type == null ? "—" : v.type) }));
      tr.appendChild(el("td", { text: String(v.fixed_version == null || v.fixed_version === "" ? "—" : v.fixed_version) }));
      tr.appendChild(el("td", { text: String(v.namespace == null ? "—" : v.namespace) }));
      tbody.appendChild(tr);
    });
    table.appendChild(tbody);
    var wrap = el("div", { class: "table-wrap" }, [table]);
    if (rows.length > ROW_LIMIT) {
      wrap.appendChild(el("p", { class: "note", text: "Mostrando " + ROW_LIMIT + " de " + rows.length + " vulnerabilidades." }));
    }
    return wrap;
  }

  function findingTable(findings) {
    if (!findings.length) return sinDatos("Sin hallazgos registrados (o CodeQL no se ejecutó: 'no evaluado', no 'limpio').");
    var rows = findings.slice().sort(function (a, b) {
      var c = sevIndex(a.severity) - sevIndex(b.severity);
      if (c !== 0) return c;
      if (String(a.file) !== String(b.file)) return String(a.file) < String(b.file) ? -1 : 1;
      return num(a.start_line) - num(b.start_line);
    });
    var table = el("table", { class: "data" });
    table.appendChild(el("caption", { class: "sr-only", text: "Hallazgos CodeQL del repositorio" }));
    var thead = el("thead");
    var hr = el("tr");
    ["Regla", "Severidad", "Archivo", "Línea"].forEach(function (h) { hr.appendChild(el("th", { scope: "col", text: h })); });
    thead.appendChild(hr);
    table.appendChild(thead);
    var tbody = el("tbody");
    rows.slice(0, ROW_LIMIT).forEach(function (f) {
      var tr = el("tr");
      tr.appendChild(el("td", { class: "mono", text: String(f.rule_id == null ? "—" : f.rule_id) }));
      tr.appendChild(el("td", {}, [sevBadge(f.severity)]));
      tr.appendChild(el("td", { text: String(f.file == null ? "—" : f.file) }));
      tr.appendChild(el("td", { class: "num", text: String(f.start_line == null ? "—" : f.start_line) }));
      tbody.appendChild(tr);
    });
    table.appendChild(tbody);
    var wrap = el("div", { class: "table-wrap" }, [table]);
    if (rows.length > ROW_LIMIT) {
      wrap.appendChild(el("p", { class: "note", text: "Mostrando " + ROW_LIMIT + " de " + rows.length + " hallazgos." }));
    }
    return wrap;
  }

  function selectRepo(name) {
    state.selectedRepo = name;
    if (state.contentEl) {
      var trs = state.contentEl.querySelectorAll("tr[data-repo]");
      for (var i = 0; i < trs.length; i++) {
        if (trs[i].getAttribute("data-repo") === name) trs[i].setAttribute("class", "selected");
        else trs[i].removeAttribute("class");
      }
    }
    renderDrilldown(state.view);
    var heading = state.drillEl ? state.drillEl.querySelector(".drill-title") : null;
    if (heading) { try { heading.focus(); } catch (e) { /* sin foco */ } }
    if (state.drillEl && state.drillEl.scrollIntoView) {
      try {
        state.drillEl.scrollIntoView({ behavior: prefersReduced() ? "auto" : "smooth", block: "start" });
      } catch (e) {
        state.drillEl.scrollIntoView(true);
      }
    }
  }

  function restoreRepoFocus(name) {
    if (!name) return;
    var nodes = document.querySelectorAll("[data-focus-id]");
    var wanted = "repo:" + name;
    for (var i = 0; i < nodes.length; i++) {
      if (nodes[i].getAttribute("data-focus-id") === wanted) {
        try { nodes[i].focus(); } catch (e) { /* sin foco */ }
        return;
      }
    }
  }

  // ---------------------------------------------------------------------------
  // Render principal y actualización
  // ---------------------------------------------------------------------------

  function renderContent(container, view) {
    if (view.filtersActive) {
      container.appendChild(el("p", {
        class: "note filter-note",
        text: "Filtros aplicados a las vistas por repositorio (" + fmtInt(view.scopeCount) + " de "
          + fmtInt(view.totalRepos) + " repositorios); los indicadores y rankings globales provienen del Analyzer (sin filtrar)."
      }));
    }
    container.appendChild(renderKpiCard(view));
    container.appendChild(renderSeverityCard(view));
    container.appendChild(renderRiskCard(view));
    container.appendChild(renderVulnsByRepoCard(view));
    container.appendChild(renderScatterCard(view));

    var pair1 = el("div", { class: "grid-2" });
    pair1.appendChild(renderTopPackagesCard(view));
    pair1.appendChild(renderTopCvesCard(view));
    container.appendChild(pair1);

    var pair2 = el("div", { class: "grid-2" });
    pair2.appendChild(renderSevByTypeCard(view));
    pair2.appendChild(renderSevByLangCard(view));
    container.appendChild(pair2);

    container.appendChild(renderTopRulesCard(view));
    container.appendChild(renderContextCard(view));
  }

  function captureFocusId() {
    var active = document.activeElement;
    if (active && active.getAttribute) return active.getAttribute("data-focus-id");
    return null;
  }

  function restoreFocusId(fid) {
    if (!fid) return;
    var nodes = document.querySelectorAll("[data-focus-id]");
    for (var i = 0; i < nodes.length; i++) {
      if (nodes[i].getAttribute("data-focus-id") === fid) {
        try { nodes[i].focus(); } catch (e) { /* sin foco */ }
        return;
      }
    }
  }

  function update() {
    var view = buildView(state.doc, state.filters);
    state.view = view;
    if (state.selectedRepo && !view.repoNames[state.selectedRepo]) state.selectedRepo = null;

    var fid = captureFocusId();
    clear(state.contentEl);
    renderContent(state.contentEl, view);
    renderDrilldown(view);
    restoreFocusId(fid);

    if (state.statusEl) {
      state.statusEl.textContent = fmtInt(view.scopeCount) + " de " + fmtInt(view.totalRepos)
        + " repositorios en las vistas por repositorio; los indicadores globales provienen del Analyzer (sin filtrar).";
    }
  }

  function scheduleUpdate() {
    if (updateTimer) clearTimeout(updateTimer);
    updateTimer = setTimeout(update, 140);
  }

  function renderShell(doc) {
    var app = document.getElementById("app");
    clear(app);
    app.appendChild(renderHeader(doc));
    app.appendChild(renderToolbar(doc));
    state.contentEl = el("div", { class: "content" });
    app.appendChild(state.contentEl);
    state.drillEl = el("div", { id: "vis-drilldown" });
    app.appendChild(state.drillEl);
    app.appendChild(renderObservations(doc));
    app.appendChild(renderLimitations(doc));
  }

  function boot() {
    if (booted) return;
    booted = true;
    var app = document.getElementById("app");
    var doc = readDocument();
    if (!doc) {
      if (app) {
        clear(app);
        app.appendChild(el("p", { class: "empty", text: "No se pudo leer el documento del Analyzer." }));
      }
      return;
    }
    state.doc = doc;
    state.filters = defaultFilters();
    initTooltip();
    renderShell(doc);
    update();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot);
  } else {
    boot();
  }
})();
