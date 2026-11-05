/**
 * es-pagination.js - 共享的 ES 分页模块
 *
 * 提供 PIT 分页和 search_after 分页两种方式
 * 被 es-tool/extract.js 等脚本复用
 */

function toShanghaiTimeString(ms) {
    return new Date(ms).toLocaleString('zh-CN', {
    timeZone: 'Asia/Shanghai',
    year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
    hour12: false
  }).replace(/\//g, '-');
}

async function detectPitSupport(esRequest) {
  try {
    const response = await esRequest('GET', '/', {});
    const version = response.version?.number || '';
    const major = parseInt(version.split('.')[0], 10);
    return major >= 7;
  } catch {
    return false;
  }
}

async function queryAllWithPitImpl(esRequest, options) {
  const { index, query, batchSize = 5000 } = options;
  const alerts = [];
  let pitId = null;
  let searchAfter = null;

  try {
    const pitResponse = await esRequest('POST', '/_pit', { keep_alive: '5m' });
    pitId = pitResponse.id;

    let hasMore = true;
    while (hasMore) {
      const searchBody = {
        query,
        size: batchSize,
        pit: { id: pitId, keep_alive: '5m' },
        sort: [{ timestamp: 'desc' }, { _id: 'desc' }]
      };

      if (searchAfter) {
        searchBody.search_after = searchAfter;
      }

      const result = await esRequest('POST', `/${index}/_search`, searchBody);

      if (result.hits?.hits?.length === 0) {
        hasMore = false;
        break;
      }

      for (const hit of result.hits.hits) {
        const src = hit._source || {};
        const fv = src.field_values || {};
        const tsMs = src.timestamp || 0;

        alerts.push({
          timestamp: toShanghaiTimeString(tsMs),
          sip: fv.sip || '',
          dip: fv.dip || '',
          sip_addr: fv.sip_addr || '',
          dip_addr: fv.dip_addr || '',
          alarm_sip: fv.alarm_sip || '',
          proto: fv.proto || '',
          host_state: fv.host_state || '',
          rule_key: fv.rule_key || '',
          attack_type: fv.attack_type || '',
          hazard_level: fv.hazard_rating || '',
          ioc: fv.ioc || '',
          vuln_name: fv.vuln_name || '',
          dport: fv.dport || '',
          sport: fv.sport || '',
          uri: fv.uri || '',
          payload: fv.payload || ''
        });
      }

      const lastHit = result.hits.hits[result.hits.hits.length - 1];
      searchAfter = lastHit?.sort;

      if (result.hits.hits.length < batchSize) {
        hasMore = false;
      }
    }
  } finally {
    if (pitId) {
      try {
        await esRequest('DELETE', '/_pit', { id: pitId });
      } catch {}
    }
  }

  return alerts;
}

async function queryAllWithSearchAfter(esRequest, options) {
  const { index, query, batchSize = 5000 } = options;
  const alerts = [];
  let searchAfter = null;

  while (true) {
    const searchBody = {
      query,
      size: batchSize,
      sort: [{ timestamp: 'desc' }, { _id: 'desc' }]
    };

    if (searchAfter) {
      searchBody.search_after = searchAfter;
    }

    const result = await esRequest('POST', `/${index}/_search`, searchBody);
    const hits = result.hits?.hits || [];

    if (hits.length === 0) break;

    for (const hit of hits) {
      const src = hit._source || {};
      const fv = src.field_values || {};
      const tsMs = src.timestamp || 0;

      alerts.push({
        timestamp: toShanghaiTimeString(tsMs),
        sip: fv.sip || '',
        dip: fv.dip || '',
        sip_addr: fv.sip_addr || '',
        dip_addr: fv.dip_addr || '',
        alarm_sip: fv.alarm_sip || '',
        proto: fv.proto || '',
        host_state: fv.host_state || '',
        rule_key: fv.rule_key || '',
        attack_type: fv.attack_type || '',
        hazard_level: fv.hazard_rating || '',
        ioc: fv.ioc || '',
        vuln_name: fv.vuln_name || '',
        dport: fv.dport || '',
        sport: fv.sport || '',
        uri: fv.uri || '',
        payload: fv.payload || ''
      });
    }

    searchAfter = hits[hits.length - 1]?.sort;

    if (hits.length < batchSize) break;
  }

  return alerts;
}

export async function queryAllWithPIT(esRequest, options) {
  const pitSupported = await detectPitSupport(esRequest);

  if (pitSupported) {
    return queryAllWithPitImpl(esRequest, options);
  } else {
    return queryAllWithSearchAfter(esRequest, options);
  }
}

export { toShanghaiTimeString };