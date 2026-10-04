# Catalyst chassis and uplink profiles

The hardware library classifies observed physical interfaces by exact structured
chassis PID, validated physical owner, and documented native port range. Physical
Interface type describes the documented copper/cage capability. Negotiated speed
continues to populate operational speed independently when the link is ready.

Profiles never create an interface merely because its chassis has a port, infer
an installed module from a bundle/license SKU, normalize an unknown PID suffix,
or equate an inactive alias with a separate physical cage. Existing inventory
values and ownership remain preserved. Unknown PIDs and unsupported port names
use the existing unresolved/template policy.

The library has 40 exact 9300-family chassis PIDs, 38 exact 9500-family PIDs
(including documented bundle/license aliases), and 12 uplink module PIDs.
Chassis recognition can be partial where port numbering is unresolved.

## 9300 chassis

Regions below use `<member>/<slot>/<port>`. Only observed eligible interfaces
inside each documented region can be typed. All profiles include the documented
1G copper management interface; management purpose/console discovery still has
its own separate reviewed profiles.

| Exact chassis PID | Fixed regions and physical type | Compatible uplink PIDs |
| --- | --- | --- |
| `C9300-24H` | GigabitEthernet `<member>/0/1–24`: `1000base-t` | `C9300-NM-4G`, `C9300-NM-4M`, `C9300-NM-2Q`, `C9300-NM-8X`, `C9300-NM-2Y` |
| `C9300-24P` | GigabitEthernet `<member>/0/1–24`: `1000base-t` | `C9300-NM-4G`, `C9300-NM-4M`, `C9300-NM-2Q`, `C9300-NM-8X`, `C9300-NM-2Y` |
| `C9300-24T` | GigabitEthernet `<member>/0/1–24`: `1000base-t` | `C9300-NM-4G`, `C9300-NM-4M`, `C9300-NM-2Q`, `C9300-NM-8X`, `C9300-NM-2Y` |
| `C9300-24U` | GigabitEthernet `<member>/0/1–24`: `1000base-t` | `C9300-NM-4G`, `C9300-NM-4M`, `C9300-NM-2Q`, `C9300-NM-8X`, `C9300-NM-2Y` |
| `C9300-24UB` | GigabitEthernet `<member>/0/1–24`: `1000base-t` | `C9300-NM-4G`, `C9300-NM-4M`, `C9300-NM-2Q`, `C9300-NM-8X`, `C9300-NM-2Y` |
| `C9300-48H` | GigabitEthernet `<member>/0/1–48`: `1000base-t` | `C9300-NM-4G`, `C9300-NM-4M`, `C9300-NM-2Q`, `C9300-NM-8X`, `C9300-NM-2Y` |
| `C9300-48P` | GigabitEthernet `<member>/0/1–48`: `1000base-t` | `C9300-NM-4G`, `C9300-NM-4M`, `C9300-NM-2Q`, `C9300-NM-8X`, `C9300-NM-2Y` |
| `C9300-48T` | GigabitEthernet `<member>/0/1–48`: `1000base-t` | `C9300-NM-4G`, `C9300-NM-4M`, `C9300-NM-2Q`, `C9300-NM-8X`, `C9300-NM-2Y` |
| `C9300-48U` | GigabitEthernet `<member>/0/1–48`: `1000base-t` | `C9300-NM-4G`, `C9300-NM-4M`, `C9300-NM-2Q`, `C9300-NM-8X`, `C9300-NM-2Y` |
| `C9300-48UB` | GigabitEthernet `<member>/0/1–48`: `1000base-t` | `C9300-NM-4G`, `C9300-NM-4M`, `C9300-NM-2Q`, `C9300-NM-8X`, `C9300-NM-2Y` |
| `C9300-24S` | GigabitEthernet `<member>/0/1–24`: `1000base-x-sfp` | `C9300-NM-4G`, `C9300-NM-4M`, `C9300-NM-2Q`, `C9300-NM-8X`, `C9300-NM-2Y` |
| `C9300-48S` | GigabitEthernet `<member>/0/1–48`: `1000base-x-sfp` | `C9300-NM-4G`, `C9300-NM-4M`, `C9300-NM-2Q`, `C9300-NM-8X`, `C9300-NM-2Y` |
| `C9300-24UX` | TenGigabitEthernet `<member>/0/1–24`: `10gbase-t` | `C9300-NM-4G`, `C9300-NM-4M`, `C9300-NM-2Q`, `C9300-NM-8X`, `C9300-NM-2Y` |
| `C9300-24UXB` | TenGigabitEthernet `<member>/0/1–24`: `10gbase-t` | `C9300-NM-4G`, `C9300-NM-4M`, `C9300-NM-2Q`, `C9300-NM-8X`, `C9300-NM-2Y` |
| `C9300-48UN` | FiveGigabitEthernet `<member>/0/1–48`: `5gbase-t` | `C9300-NM-4G`, `C9300-NM-4M`, `C9300-NM-2Q`, `C9300-NM-8X`, `C9300-NM-2Y` |
| `C9300-48UXM` | TwoGigabitEthernet `<member>/0/1–36`: `2.5gbase-t`; TenGigabitEthernet `<member>/0/37–48`: `10gbase-t` | `C9300-NM-4G`, `C9300-NM-4M`, `C9300-NM-2Q`, `C9300-NM-8X`, `C9300-NM-2Y`, `C3850-NM-4-1G` |
| `C9300L-24T-4G` | GigabitEthernet `<member>/0/1–24`: `1000base-t`; GigabitEthernet `<member>/1/1–4`: `1000base-x-sfp` | Fixed uplinks |
| `C9300L-24P-4G` | GigabitEthernet `<member>/0/1–24`: `1000base-t`; GigabitEthernet `<member>/1/1–4`: `1000base-x-sfp` | Fixed uplinks |
| `C9300L-24T-4X` | GigabitEthernet `<member>/0/1–24`: `1000base-t`; TenGigabitEthernet `<member>/1/1–4`: `10gbase-x-sfpp` | Fixed uplinks |
| `C9300L-24P-4X` | GigabitEthernet `<member>/0/1–24`: `1000base-t`; TenGigabitEthernet `<member>/1/1–4`: `10gbase-x-sfpp` | Fixed uplinks |
| `C9300L-48T-4G` | GigabitEthernet `<member>/0/1–48`: `1000base-t`; GigabitEthernet `<member>/1/1–4`: `1000base-x-sfp` | Fixed uplinks |
| `C9300L-48P-4G` | GigabitEthernet `<member>/0/1–48`: `1000base-t`; GigabitEthernet `<member>/1/1–4`: `1000base-x-sfp` | Fixed uplinks |
| `C9300L-48PF-4G` | GigabitEthernet `<member>/0/1–48`: `1000base-t`; GigabitEthernet `<member>/1/1–4`: `1000base-x-sfp` | Fixed uplinks |
| `C9300L-48T-4X` | GigabitEthernet `<member>/0/1–48`: `1000base-t`; TenGigabitEthernet `<member>/1/1–4`: `10gbase-x-sfpp` | Fixed uplinks |
| `C9300L-48P-4X` | GigabitEthernet `<member>/0/1–48`: `1000base-t`; TenGigabitEthernet `<member>/1/1–4`: `10gbase-x-sfpp` | Fixed uplinks |
| `C9300L-48PF-4X` | GigabitEthernet `<member>/0/1–48`: `1000base-t`; TenGigabitEthernet `<member>/1/1–4`: `10gbase-x-sfpp` | Fixed uplinks |
| `C9300L-24UXG-4X` | TenGigabitEthernet `<member>/1/1–4`: `10gbase-x-sfpp` | Fixed uplinks |
| `C9300L-24UXG-2Q` | FortyGigabitEthernet `<member>/1/1–2`: `40gbase-x-qsfpp` | Fixed uplinks |
| `C9300L-48UXG-4X` | GigabitEthernet `<member>/0/1–36`: `1000base-t`; TenGigabitEthernet `<member>/0/37–48`: `10gbase-t`; TenGigabitEthernet `<member>/1/1–4`: `10gbase-x-sfpp` | Fixed uplinks |
| `C9300L-48UXG-2Q` | GigabitEthernet `<member>/0/1–36`: `1000base-t`; TenGigabitEthernet `<member>/0/37–48`: `10gbase-t`; FortyGigabitEthernet `<member>/1/1–2`: `40gbase-x-qsfpp` | Fixed uplinks |
| `C9300LM-48T-4Y` | GigabitEthernet `<member>/0/1–48`: `1000base-t`; TwentyFiveGigE `<member>/1/1–4`: `25gbase-x-sfp28` | Fixed uplinks |
| `C9300LM-24U-4Y` | GigabitEthernet `<member>/0/1–24`: `1000base-t`; TwentyFiveGigE `<member>/1/1–4`: `25gbase-x-sfp28` | Fixed uplinks |
| `C9300LM-48U-4Y` | GigabitEthernet `<member>/0/1–48`: `1000base-t`; TwentyFiveGigE `<member>/1/1–4`: `25gbase-x-sfp28` | Fixed uplinks |
| `C9300LM-48UX-4Y` | TwentyFiveGigE `<member>/1/1–4`: `25gbase-x-sfp28` | Fixed uplinks |
| `C9300X-12Y` | TwentyFiveGigE `<member>/0/1–12`: `25gbase-x-sfp28` | `C9300X-NM-2C`, `C9300X-NM-8M`, `C9300X-NM-8Y` |
| `C9300X-24Y` | TwentyFiveGigE `<member>/0/1–24`: `25gbase-x-sfp28` | `C9300X-NM-2C`, `C9300X-NM-8M`, `C9300X-NM-8Y`, `C9300X-NM-4C` |
| `C9300X-48HX` | TenGigabitEthernet `<member>/0/1–48`: `10gbase-t` | `C9300X-NM-2C`, `C9300X-NM-8M`, `C9300X-NM-8Y`, `C9300X-NM-4C` |
| `C9300X-48TX` | TenGigabitEthernet `<member>/0/1–48`: `10gbase-t` | `C9300X-NM-2C`, `C9300X-NM-8M`, `C9300X-NM-8Y`, `C9300X-NM-4C` |
| `C9300X-24HX` | TenGigabitEthernet `<member>/0/1–24`: `10gbase-t` | `C9300X-NM-2C`, `C9300X-NM-8M`, `C9300X-NM-8Y` |
| `C9300X-48HXN` | Port numbering unresolved | `C9300X-NM-2C`, `C9300X-NM-8M`, `C9300X-NM-8Y` |

C9300L-24UXG-4X/-2Q, C9300LM-48UX-4Y and C9300X-48HXN keep mixed
fixed downlinks unresolved where the published descriptions/diagrams disagree
or omit a reliable port split. Known management and fixed uplink regions remain
eligible. C9300X-48HXN uses chassis-specific network-module overrides: 8M/8Y
ports 1–6 are usable on the project's IOS XE 17.9+ baseline; ports 7–8 have no
eligible mapping. Ordinary 8M/8Y profiles retain their eight usable ports on
compatible non-HXN chassis.

## 9500 chassis

Traditional modular 9500s use slot 0 for fixed ports and slot 1 for installed
network modules. High-performance and 9500X fixed ports use slot 0 throughout.

| Base chassis PID | Fixed regions and physical type | Compatible uplink PIDs |
| --- | --- | --- |
| `C9500-12Q` | FortyGigabitEthernet `<member>/0/1–12`: `40gbase-x-qsfpp` | Fixed chassis ports |
| `C9500-24Q` | FortyGigabitEthernet `<member>/0/1–24`: `40gbase-x-qsfpp` | Fixed chassis ports |
| `C9500-16X` | TenGigabitEthernet `<member>/0/1–16`: `10gbase-x-sfpp` | `C9500-NM-8X`, `C9500-NM-2Q` |
| `C9500-40X` | TenGigabitEthernet `<member>/0/1–40`: `10gbase-x-sfpp` | `C9500-NM-8X`, `C9500-NM-2Q` |
| `C9500-24Y4C` | TwentyFiveGigE `<member>/0/1–24`: `25gbase-x-sfp28`; HundredGigE `<member>/0/25–28`: `100gbase-x-qsfp28` | Fixed chassis ports |
| `C9500-48Y4C` | TwentyFiveGigE `<member>/0/1–48`: `25gbase-x-sfp28`; HundredGigE `<member>/0/49–52`: `100gbase-x-qsfp28` | Fixed chassis ports |
| `C9500-32C` | HundredGigE `<member>/0/1–32`: `100gbase-x-qsfp28` | Fixed chassis ports |
| `C9500-32QC` | Port numbering unresolved | Fixed chassis ports |
| `C9500X-28C8D` | HundredGigE `<member>/0/1–14`: `100gbase-x-qsfp28`; FourHundredGigE `<member>/0/15–22`: `400gbase-x-qsfpdd`; HundredGigE `<member>/0/23–36`: `100gbase-x-qsfp28` | Fixed chassis ports |
| `C9500X-60L4D` | FiftyGigabitEthernet `<member>/0/1–30`: `50gbase-x-sfp56`; FourHundredGigE `<member>/0/31–34`: `400gbase-x-qsfpdd`; FiftyGigabitEthernet `<member>/0/35–64`: `50gbase-x-sfp56` | Fixed chassis ports |

C9500-32QC physical typing remains unresolved: its 40G and 100G names overlap
and port conversion can deactivate other cages. The mapping needs explicit
conversion/breakout evidence. Management copper capability remains known.
Breakout lane names and traditional QSFP-to-10G aliases have no physical profile.
IOS XE can report inactive aliases, so link state alone cannot resolve these
relationships.

Documented exact aliases retain their ordering-guide evidence in returned port
facts. Bundled network modules still require current hardware inventory.

| Exact alias | Base physical chassis |
| --- | --- |
| `C9500-16X-2Q` | `C9500-16X` |
| `C9500-40X-2Q` | `C9500-40X` |
| `C9500-24X` | `C9500-16X` |
| `C9500-48X` | `C9500-40X` |
| `C9500-12Q-A` | `C9500-12Q` |
| `C9500-12Q-E` | `C9500-12Q` |
| `C9500-24Q-A` | `C9500-24Q` |
| `C9500-24Q-E` | `C9500-24Q` |
| `C9500-16X-A` | `C9500-16X` |
| `C9500-16X-E` | `C9500-16X` |
| `C9500-40X-A` | `C9500-40X` |
| `C9500-40X-E` | `C9500-40X` |
| `C9500-24Y4C-A` | `C9500-24Y4C` |
| `C9500-24Y4C-E` | `C9500-24Y4C` |
| `C9500-48Y4C-A` | `C9500-48Y4C` |
| `C9500-48Y4C-E` | `C9500-48Y4C` |
| `C9500-32C-A` | `C9500-32C` |
| `C9500-32C-E` | `C9500-32C` |
| `C9500-32QC-A` | `C9500-32QC` |
| `C9500-32QC-E` | `C9500-32QC` |
| `C9500-16X-2Q-A` | `C9500-16X` |
| `C9500-16X-2Q-E` | `C9500-16X` |
| `C9500-40X-2Q-A` | `C9500-40X` |
| `C9500-40X-2Q-E` | `C9500-40X` |
| `C9500-24X-A` | `C9500-16X` |
| `C9500-24X-E` | `C9500-16X` |
| `C9500-48X-A` | `C9500-40X` |
| `C9500-48X-E` | `C9500-40X` |

## Installed uplink modules

A unique PIM in the physical owner's structured hardware inventory must report
an explicitly compatible module PID. The library cannot use a port's name or a
chassis order bundle as proof that a particular module is installed.

| Module PID | Eligible slot-1 native regions | Serialized placement profile |
| --- | --- | --- |
| `C9300-NM-4G` | GigabitEthernet `<member>/1/1–4`: `1000base-x-sfp` | Corroborated 9300 slot 1 |
| `C9300-NM-4M` | TenGigabitEthernet `<member>/1/1–4`: `10gbase-t` | Corroborated 9300 slot 1 |
| `C9300-NM-2Q` | FortyGigabitEthernet `<member>/1/1–2`: `40gbase-x-qsfpp` | Corroborated 9300 slot 1 |
| `C9300-NM-8X` | TenGigabitEthernet `<member>/1/1–8`: `10gbase-x-sfpp` | Corroborated 9300 slot 1 |
| `C9300-NM-2Y` | TwentyFiveGigE `<member>/1/1–2`: `25gbase-x-sfp28` | Corroborated 9300 slot 1 |
| `C9300X-NM-2C` | HundredGigE `<member>/1/1–2`: `100gbase-x-qsfp28` | Corroborated 9300 slot 1 |
| `C9300X-NM-4C` | HundredGigE `<member>/1/1–4`: `100gbase-x-qsfp28` | Corroborated 9300 slot 1 |
| `C9300X-NM-8M` | TenGigabitEthernet `<member>/1/1–8`: `10gbase-t` | Corroborated 9300 slot 1 |
| `C9300X-NM-8Y` | TwentyFiveGigE `<member>/1/1–8`: `25gbase-x-sfp28` | Corroborated 9300 slot 1 |
| `C3850-NM-4-1G` | GigabitEthernet `<member>/1/1–4`: `1000base-x-sfp` | Corroborated 9300 slot 1 |
| `C9500-NM-8X` | TenGigabitEthernet `<member>/1/1–8`: `10gbase-x-sfpp` | Await structured placement evidence |
| `C9500-NM-2Q` | FortyGigabitEthernet `<member>/1/1–2`: `40gbase-x-qsfpp` | Await structured placement evidence |

The existing lab's C3850-NM-4-1G compatibility remains restricted to C9300-48UXM.
Blank airflow covers are not serialized network-module profiles.

## Serialized modules and optics

Eligible 9300 modules require unique PID/serial agreement between
`device-hardware-oper` and `platform-oper`, verified chassis identity and member,
and the observed slot-1 parent/name/location/presence/removability relationships.
New modules require the model's module/FRU classification; the lab's `comp-port`
quirk remains restricted to its existing C3850 profile. Only eligible observed
interfaces with agreeing physical capability can be assigned to the Module.

Optics require their own corroborated PID, serial, manufacturer, presence,
physical-port identity, chassis placement and a uniquely resolved optical uplink
parent. SFP/SFP+/SFP28/QSFP+/QSFP28 assets use native nested ModuleBays/Modules;
copper 4M/8M ports cannot establish optical cages. Existing Interface device,
module and cable relationships remain preserved.

9500 module port capability is documented, but serialized module/optic placement
remains report-only until structured platform data verifies the appropriate
9500 placement convention. This library does not add StackWise Virtual ownership,
advanced breakout relationships, new PSU profiles, console profiles or software
images.

## Evidence and maintenance

Profiles embed Cisco source URLs, relevant sections, exact model, region and
profile identity in `discovery.interfaces[].hardware_profile`. Installed-module
facts additionally retain the structured inventory identity used for the match.
Alias evidence includes the ordering guide. Source dictionaries remain separate
from native Nautobot fields; no custom fields are added.

The implementation lives in `jobs/adapters/cisco_c9300_profiles.py`,
`cisco_c9500_profiles.py`, and shared `cisco_hardware_profiles.py`. A future
profile requires an exact documented PID, complete native family/slot/port
meaning, explicit compatibility and source evidence. Per-chassis module region
overrides capture documented restrictions without changing the generic module.
Unresolved documentation is a reason to retain observations and defer writes.

Primary references:

- [Cisco Catalyst 9300 architecture](https://www.cisco.com/c/en/us/products/collateral/switches/catalyst-9300-series-switches/nb-06-cat9300-architecture-cte-en.html)
- [9300 hardware and chassis overview](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/hardware/install/b_c9300_hig/Product-overview.html)
- [9300 network-module installation and compatibility](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/hardware/install/b_c9300_hig/Installing-a-network-module.html)
- [9500 hardware overview](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9500/hardware/install/b_catalyst_9500_hig/9500_product-overview.html)
- [9500X hardware and port numbering](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9500/hardware/install/b-c9500x-hig/9500x_product-overview.html)
- [9500 native interface and breakout meanings](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9500/software/release/17-12/configuration_guide/int_hw/b_1712_int_and_hw_9500_cg/configuring_interface_characteristics.html)
- [9500X FiftyGigE spelling](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9500/software/release/17-13/configuration_guide/ha/b_1713_ha_9500_cg/configuring_cisco_stackwise_virtual.html)
- [Native interface YANG, IOS XE 17.9.1](https://raw.githubusercontent.com/YangModels/yang/main/vendor/cisco/xe/1791/Cisco-IOS-XE-interfaces.yang)
- [Native interface YANG, IOS XE 17.18.1](https://raw.githubusercontent.com/YangModels/yang/main/vendor/cisco/xe/17181/Cisco-IOS-XE-interfaces.yang)

## Validation

Version `0.16.0-dev` passed 628 offline regressions and 141 checks against native
Nautobot 3.2.5 models. Temporary native inventory changes were rolled back.
Constructed 9500/9500X sources verified native 10G/25G/50G/100G/400G choices,
zero-write previews and repeats, and preservation of populated interface types.
Source regressions cover exact PID/compatibility boundaries, HXN restrictions,
ambiguous regions, serialized parent/port disagreements, copper optic rejection,
and matching JSON report representations.

Live RESTCONF preview on the C9300-48UXM running IOS XE 17.18.4 classified 53
physical interfaces through the library and issued zero database mutation
statements. Real Celery preview and repeat-apply jobs both succeeded on the
installed version, with equal before/after inventory and IPAM snapshots,
preserved power cables and no custom-field changes. Existing unresolved
observations and the preserved Vlan2 type difference remained visible.
Reports are retained in the ignored `artifacts/hardware-library/` directory.

9500 coverage has documented-source, constructed-source and native-model
validation; no live 9500 was available for this increment. Its serialized
placement remains deferred as described above.
