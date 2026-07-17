/**
 * VyOS router management model.
 *
 * Manages a VyOS router over SSH: read the running configuration, apply
 * `set`/`delete` configuration commands through `vbash` (with `commit`/`save`),
 * and run arbitrary operational- or config-mode commands.
 *
 * VyOS is peculiar: configuration mode requires `vbash` sourcing the Vyatta
 * `script-template`; a plain `ssh host 'configure; set ...'` does NOT work.
 * Operational reads go through the `vyatta-op-cmd-wrapper`. This model encodes
 * those requirements so callers work in terms of plain `set`/`delete` paths.
 *
 * The SSH transport is deliberately isolated in {@link sshExec}. Once
 * model-to-model calls (`context.runModel`) land in the distributed binary,
 * that one helper can be swapped to invoke `@swamp/ssh` (`exec`/`script`)
 * instead of shelling out, with no change to the VyOS method logic. Every method
 * also accepts an injectable `_ssh` runner so the logic is unit-testable without
 * a live router.
 *
 * @module
 */
import { GlobalArgsSchema, SCRIPT_TEMPLATE, sshExec } from "./core.ts";
import type { CheckContext } from "./core.ts";
import { rawCheckMethods, rawMethods, rawResources } from "./raw.ts";
import {
  routerAdvertCheckMethods,
  routerAdvertMethods,
  routerAdvertResources,
} from "./router_advert.ts";
import {
  wireguardCheckMethods,
  wireguardMethods,
  wireguardResources,
} from "./wireguard.ts";
import {
  interfaceCheckMethods,
  interfaceMethods,
  interfaceResources,
} from "./interface.ts";
import {
  firewallCheckMethods,
  firewallMethods,
  firewallResources,
} from "./firewall.ts";
import { natCheckMethods, natMethods, natResources } from "./nat.ts";
import {
  staticRouteCheckMethods,
  staticRouteMethods,
  staticRouteResources,
} from "./routes.ts";
import {
  dnsForwardingCheckMethods,
  dnsForwardingMethods,
  dnsForwardingResources,
} from "./dns_forwarding.ts";
import { dhcpCheckMethods, dhcpMethods, dhcpResources } from "./dhcp.ts";
import {
  containerCheckMethods,
  containerMethods,
  containerResources,
} from "./container.ts";
import { pbrCheckMethods, pbrMethods, pbrResources } from "./pbr.ts";

/** VyOS router management model definition. */
export const model = {
  type: "@shrug/vyos",
  version: "2026.07.16.1",
  description:
    "Manage a VyOS router over SSH: read config, apply set/delete via vbash, run commands.",
  globalArguments: GlobalArgsSchema,
  resources: {
    ...rawResources,
    ...routerAdvertResources,
    ...wireguardResources,
    ...interfaceResources,
    ...firewallResources,
    ...natResources,
    ...staticRouteResources,
    ...dnsForwardingResources,
    ...dhcpResources,
    ...containerResources,
    ...pbrResources,
  },
  checks: {
    "reachable": {
      description:
        "Verify the router's config mode is reachable over SSH before applying.",
      labels: ["live"],
      appliesTo: [
        ...rawCheckMethods,
        ...routerAdvertCheckMethods,
        ...wireguardCheckMethods,
        ...interfaceCheckMethods,
        ...firewallCheckMethods,
        ...natCheckMethods,
        ...staticRouteCheckMethods,
        ...dnsForwardingCheckMethods,
        ...dhcpCheckMethods,
        ...containerCheckMethods,
        ...pbrCheckMethods,
      ],
      execute: async (context: CheckContext): Promise<
        { pass: boolean; errors?: string[] }
      > => {
        const cfg = context.globalArgs;
        context.logger.info("Probing VyOS config mode on {host}", {
          host: cfg.host,
        });
        const probe = `source ${SCRIPT_TEMPLATE}\nconfigure\nexit\n`;
        const result = await sshExec(cfg, {
          command: ["/bin/vbash", "-s"],
          stdin: probe,
        });
        if (result.code !== 0) {
          return {
            pass: false,
            errors: [
              `cannot reach VyOS config mode on ${cfg.host}: ${
                result.stderr.trim() || `exit ${result.code}`
              }`,
            ],
          };
        }
        return { pass: true };
      },
    },
  },
  methods: {
    ...rawMethods,
    ...routerAdvertMethods,
    ...wireguardMethods,
    ...interfaceMethods,
    ...firewallMethods,
    ...natMethods,
    ...staticRouteMethods,
    ...dnsForwardingMethods,
    ...dhcpMethods,
    ...containerMethods,
    ...pbrMethods,
  },
};
