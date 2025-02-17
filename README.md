<h1>
<p align="center">
    <img src="docs/logo.png" alt="Logo" width="200">
  <br>BPFluga
</h1>
<p align="center">
  An agentless eBPF observability tool to deploy eBPF programs to remote machines and collect metrics from them at scale.
  </p>
</p>

# About

> [!NOTE]  
> This is my toy and side project to learn eBPF. I'm not an expert in this field (yet?). Use it at your own risk.

BPFluga is an agentless eBPF observability tool designed for modern distributed systems. Built in Go using the cilium/ebpf library.

Inspired by the graceful beluga whale, bpfluga offers a streamlined and efficient solution to monitor and debug systems. Its agentless architecture allows you to deploy, manage, and detach eBPF programs across your infrastructure via simple SSH commands.

# Features

#### Agentless Deployment:
Deploy eBPF programs remotely without installing persistent agents.

#### Dynamic eBPF Management:
Load, pin, and detach eBPF code programatically based on conditions that you define in a declarative way.

#### Visualization:
Visualize your collected metrics in Grafana.

#### RAG:
Use the integrated RAG to answer questions about your collected metrics.


**Once the VM is created:**

Install Go

`sudo snap install go --classic`

Create a symlink to the asm-generic directory, to fix this error:

```
In file included from /usr/include/linux/bpf.h:11:
/usr/include/linux/types.h:5:10: fatal error: 'asm/types.h' file not found
    5 | #include <asm/types.h>
      |          ^~~~~~~~~~~~~
```

`ln -sf /usr/include/asm-generic/ /usr/include/asm`

Also install the following packages:

`go get github.com/cilium/ebpf`
`go get github.com/cilium/ebpf/link`
