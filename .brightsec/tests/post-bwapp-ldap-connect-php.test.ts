import { test, before, after } from 'node:test';
import { SecRunner } from '@sectester/runner';
import { AttackParamLocation, HttpMethod } from '@sectester/scan';

const timeout = 40 * 60 * 1000;
const baseUrl = process.env.BRIGHT_TARGET_URL!;

let runner!: SecRunner;

before(async () => {
  runner = new SecRunner({
    hostname: process.env.BRIGHT_HOSTNAME!,
    projectId: process.env.BRIGHT_PROJECT_ID!
  });

  await runner.init();
});

after(() => runner.clear());

test('POST /bWAPP/ldap_connect.php', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: ['ldapi', 'csrf', 'xss', 'insecure_tls_configuration', 'unvalidated_redirect'],
      attackParamLocations: [AttackParamLocation.BODY],
      starMetadata: {
        code_source: "lsndr/bWAPP:master",
        databases: ["MySQL"],
        user_roles: {
          roles: []
        }
      },
      poolSize: +process.env.SECTESTER_SCAN_POOL_SIZE || undefined
    })
    .setFailFast(false)
    .timeout(timeout)
    .run({
      method: HttpMethod.POST,
      url: `${baseUrl}/bWAPP/ldap_connect.php`,
      body: {
        login: 'bee@bwapp.local',
        password: 'examplePassword',
        server: 'ldap.example.com',
        dn: 'DC=bwapp,DC=local'
      },
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
    });
});