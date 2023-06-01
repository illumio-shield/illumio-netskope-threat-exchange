# Illumio Plugin for Netskope Threat Exchange  

The Illumio plugin for Netskope Threat Exchange provides a configurable way to retrieve threat IoCs within a given policy scope from the Illumio Policy Compute Engine (PCE).  

The policy scope consists of one or more PCE Label key:value pairs - workloads matching the scope will be polled on a configurable interval and added to an IoC threat list. Workloads in this list can then be attached to Netskope policy for granular access control.  

Multiple plugin instances can be defined for specific access boundaries, such as quarantine zones, production workloads, or other access-restricted policy scopes.  

See the User Guide for detailed installation and configuration instructions.  

## Support  

The Illumio plugin for Netskope Threat Exchange is released and distributed as open source software subject to the included [LICENSE](LICENSE). Illumio has no obligation or responsibility related to the plugin with respect to support, maintenance, availability, security or otherwise. Please read the entire [LICENSE](LICENSE) for additional information regarding the permissions and limitations. Support is offered on a best-effort basis through the Illumio app integrations team and project contributors.  

## License  

Copyright 2023 Illumio  

```
   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
```
