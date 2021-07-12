# top-proxy

![example workflow](https://github.com/Perseus/top-proxy/actions/workflows/rust.yml/badge.svg)

Meant to serve as a middleman between game clients and the gateserver and do the following ->

* Filter unwanted traffic
* Support additional network-level features without making changes to the GateServer
* Provide rudimentary DDoS protection
* Support Linux (as opposed to the GateServer), allowing it to be deployed across multiple regions for a cheaper price
* Due to the middleman nature, can increase reliability of the server. If multiple instances are deployed, even if one crashes, players can connect to another.
* Support real-time analytics and metrics (networking, gameplay)