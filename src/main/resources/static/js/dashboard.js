(function () {
  'use strict';

  const pollMs = (parseInt(document.body.dataset.pollSeconds, 10) || 3) * 1000;
  const rows = document.getElementById('alert-rows');
  const filter = document.getElementById('severity-filter');
  const count = document.getElementById('count');
  const status = document.getElementById('status');

  const SEVERITIES = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
  const TECHNIQUE = /^T\d{4}(\.\d{3})?$/;

  let lastAlerts = [];
  let expandedId = null;

  // Every cell is built with textContent / append, never innerHTML:
  // log data is attacker-controlled and must never be parsed as HTML.
  function td(child, className) {
    const cell = document.createElement('td');
    if (className) cell.className = className;
    if (typeof child === 'string') {
      cell.textContent = child;
    } else if (child) {
      cell.append(child);
    }
    return cell;
  }

  function badge(severity) {
    const span = document.createElement('span');
    const known = SEVERITIES.includes(severity);
    span.className = 'badge ' + (known ? 'sev-' + severity.toLowerCase() : 'sev-unknown');
    span.textContent = severity;
    return span;
  }

  function mitreCell(alert) {
    const technique = alert.mitreTechnique || '';
    const label = technique + (alert.mitreTactic ? ' \u00b7 ' + alert.mitreTactic : '');
    if (!TECHNIQUE.test(technique)) {
      return td(label);
    }
    const link = document.createElement('a');
    link.href = 'https://attack.mitre.org/techniques/' + technique.replace('.', '/') + '/';
    link.target = '_blank';
    link.rel = 'noopener noreferrer';
    link.textContent = label;
    link.addEventListener('click', (e) => e.stopPropagation());
    return td(link);
  }

  function formatTime(iso) {
    const d = new Date(iso);
    return isNaN(d.getTime()) ? String(iso) : d.toLocaleString();
  }

  function render(alerts) {
    lastAlerts = alerts;
    rows.replaceChildren();
    count.textContent = alerts.length;

    if (alerts.length === 0) {
      const tr = document.createElement('tr');
      const cell = td('No alerts', 'empty');
      cell.colSpan = 5;
      tr.append(cell);
      rows.append(tr);
      return;
    }

    for (const a of alerts) {
      const tr = document.createElement('tr');
      tr.className = 'alert-row';
      tr.append(
        td(formatTime(a.eventTimestamp)),
        td(badge(a.severity)),
        td(a.ruleId + ' \u2013 ' + a.ruleTitle),
        mitreCell(a),
        td(a.sourceIp || ''));
      tr.addEventListener('click', () => {
        expandedId = expandedId === a.id ? null : a.id;
        render(lastAlerts);
      });
      rows.append(tr);

      if (a.id === expandedId) {
        const detailRow = document.createElement('tr');
        const pre = document.createElement('pre');
        pre.textContent = a.evidence || '(no evidence recorded)';
        const cell = td(pre, 'detail');
        cell.colSpan = 5;
        detailRow.append(cell);
        rows.append(detailRow);
      }
    }
  }

  async function load() {
    const severity = filter.value;
    const url = '/api/alerts' + (severity ? '?severity=' + encodeURIComponent(severity) : '');
    try {
      const response = await fetch(url);
      if (!response.ok) {
        throw new Error('HTTP ' + response.status);
      }
      render(await response.json());
      status.textContent = 'Updated ' + new Date().toLocaleTimeString();
      status.className = 'ok';
    } catch (e) {
      status.textContent = 'Backend unreachable (' + e.message + ')';
      status.className = 'err';
    }
  }

  filter.addEventListener('change', load);
  load();
  setInterval(load, pollMs);
})();