import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  THREAT_CATEGORIES,
  CATEGORY_ACTION,
  cleanIoc,
  deriveThreatTopics,
  loadThreatCategories,
} from '../../skills/secops-alert-analysis/scripts/shared/threat-categories.js';

describe('threat-categories 配置', () => {
  it('c2_rat 不包含「代理工具」（VPN/frp/ToDesk/向日葵/CPolar 不应归入远控木马/C2）', () => {
    assert.ok(!THREAT_CATEGORIES.c2_rat.includes('代理工具'), 'THREAT_CATEGORIES.c2_rat 不应含 代理工具');
    // 从 JSON 文件加载的实例也应一致
    const fromFile = loadThreatCategories();
    assert.ok(!fromFile.c2_rat.includes('代理工具'), 'loadThreatCategories().c2_rat 不应含 代理工具');
    // 保留远控木马/僵尸网络/后门程序
    for (const t of ['远控木马', '僵尸网络', '后门程序']) {
      assert.ok(THREAT_CATEGORIES.c2_rat.includes(t), `c2_rat 应保留 ${t}`);
    }
  });

  it('CATEGORY_ACTION 含四个专项的处置建议文案', () => {
    for (const k of ['weak_password', 'c2_rat', 'mining_ransom']) {
      assert.ok(typeof CATEGORY_ACTION[k] === 'string' && CATEGORY_ACTION[k].length > 0, `${k} 应有处置建议`);
    }
  });
});

describe('cleanIoc', () => {
  it('剥离前导数字编号前缀', () => {
    assert.equal(cleanIoc('24669-发现sip协议爆破行为'), '发现sip协议爆破行为');
    assert.equal(cleanIoc('268439785-Dasan GPON路由器认证绕过（CVE-2018-10561）'), 'Dasan GPON路由器认证绕过（CVE-2018-10561）');
  });

  it('无前缀或空值安全返回', () => {
    assert.equal(cleanIoc('普通标签'), '普通标签');
    assert.equal(cleanIoc(''), '');
    assert.equal(cleanIoc(null), '');
    assert.equal(cleanIoc(undefined), '');
  });
});

describe('deriveThreatTopics.details', () => {
  const compromised = [
    { ip: '10.1.1.1', count: 50, attack_types: [{ type: '弱口令', count: 50 }], last_seen: '2026-07-18 23:00:00', first_seen: '2026-07-18 00:00:00' },
    { ip: '10.1.1.2', count: 30, attack_types: [{ type: '非授权访问/权限绕过', count: 30 }], last_seen: '2026-07-18 22:00:00' },
    { ip: '10.1.1.3', count: 20, attack_types: [{ type: '远控木马', count: 20 }], last_seen: '2026-07-18 21:00:00' },
    { ip: '10.1.1.4', count: 10, attack_types: [{ type: '挖矿', count: 10 }], last_seen: '2026-07-18 20:00:00' },
    // 代理工具主机：应被 C2 排除，也不应进入其他专项
    { ip: '10.1.1.5', count: 5, attack_types: [{ type: '代理工具', count: 5 }], last_seen: '2026-07-18 19:00:00' },
  ];
  const domains = [
    { ioc: '268569560-发现后门程序 Mozi', attack_types: [{ type: '后门程序', count: 3 }] },
  ];
  const attackTypes = [
    { type: '弱口令', count: 50 },
    { type: '非授权访问/权限绕过', count: 30 },
    { type: '远控木马', count: 20 },
    { type: '挖矿', count: 10 },
    { type: '代理工具', count: 5 },
    { type: '后门程序', count: 3 },
  ];

  it('weak_password.details 从 compromised 筛选命中主机，按攻击次数降序，带 action', () => {
    const { weak_password } = deriveThreatTopics({ attackTypes, ips: [], domains, compromised });
    assert.equal(weak_password.details.length, 2);
    assert.equal(weak_password.details[0].victimIp, '10.1.1.1');
    assert.equal(weak_password.details[1].victimIp, '10.1.1.2');
    assert.equal(weak_password.details[0].lastTime, '2026-07-18 23:00:00');
    // attackTypes 为命中该类别的攻击类型子集
    assert.deepEqual(weak_password.details[0].attackTypes, [{ type: '弱口令', count: 50 }]);
    assert.match(weak_password.details[0].action, /弱口令整改/);
  });

  it('c2_rat.details 不含代理工具主机，只含远控木马/后门程序类', () => {
    const { c2_rat } = deriveThreatTopics({ attackTypes, ips: [], domains, compromised });
    assert.equal(c2_rat.details.length, 1);
    assert.equal(c2_rat.details[0].victimIp, '10.1.1.3');
    assert.ok(!c2_rat.details.some((d) => d.victimIp === '10.1.1.5'), '代理工具主机不应进入 c2_rat');
    assert.match(c2_rat.details[0].action, /病毒查杀/);
    // domains 经 cleanIoc 清洗
    assert.deepEqual(c2_rat.domains, ['发现后门程序 Mozi']);
  });

  it('mining_ransom.details 包含挖矿主机', () => {
    const { mining_ransom } = deriveThreatTopics({ attackTypes, ips: [], domains, compromised });
    assert.equal(mining_ransom.details.length, 1);
    assert.equal(mining_ransom.details[0].victimIp, '10.1.1.4');
    assert.match(mining_ransom.details[0].action, /矿池阻断/);
  });

});
