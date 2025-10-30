# <ins> Nvidia 7 </ins> : Enterprise Security & Compliance: Hardening Run.ai + HPC on Rocky Linux

## Overview

#### Implement enterprise-grade security, compliance, and hardening for your HPC and AI platform, including regulatory compliance (HIPAA, SOC2, GDPR), network security, and access controls.

--

## Step 1: Rocky Linux Security Hardening

```python
#!/bin/bash
# enterprise_security_hardening.sh

echo " Implementing Enterprise Security Hardening on Rocky Linux"

# 1. System updates and core security
sudo dnf update -y
sudo dnf install -y aide selinux-policy-targeted audit

# 2. Configure SELinux for HPC/AI workloads
sudo setenforce 1
sudo sed -i 's/^SELINUX=permissive/SELINUX=enforcing/' /etc/selinux/config

# 3. Configure audit system
sudo systemctl enable auditd
sudo systemctl start auditd

# 4. Filesystem security
echo "tmpfs /tmp tmpfs defaults,nosuid,nodev,noexec 0 0" | sudo tee -a /etc/fstab
echo "tmpfs /var/tmp tmpfs defaults,nosuid,nodev,noexec 0 0" | sudo tee -a /etc/fstab

# 5. SSH hardening
sudo sed -i 's/^#PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
sudo sed -i 's/^#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
sudo sed -i 's/^#X11Forwarding yes/X11Forwarding no/' /etc/ssh/sshd_config
sudo sed -i 's/^#MaxAuthTries 6/MaxAuthTries 3/' /etc/ssh/sshd_config
sudo systemctl restart sshd

# 6. Configure firewall for enterprise services
sudo firewall-cmd --permanent --add-service=ssh
sudo firewall-cmd --permanent --add-port=6443/tcp  # Kubernetes API
sudo firewall-cmd --permanent --add-port=10250/tcp # Kubelet API
sudo firewall-cmd --permanent --add-port=2379-2380/tcp # etcd
sudo firewall-cmd --permanent --add-port=8472/udp  # Flannel
sudo firewall-cmd --permanent --remove-service=dhcpv6-client
sudo firewall-cmd --permanent --remove-service=cockpit
sudo firewall-cmd --reload

# 7. Configure system limits for security
echo "* hard core 0" | sudo tee -a /etc/security/limits.conf
echo "* hard nproc 65536" | sudo tee -a /etc/security/limits.conf
echo "* hard nofile 65536" | sudo tee -a /etc/security/limits.conf

# 8. Kernel security parameters
echo "net.ipv4.ip_forward = 1" | sudo tee -a /etc/sysctl.conf
echo "net.ipv4.conf.all.rp_filter = 1" | sudo tee -a /etc/sysctl.conf
echo "net.ipv4.conf.default.rp_filter = 1" | sudo tee -a /etc/sysctl.conf
echo "net.ipv4.conf.all.accept_redirects = 0" | sudo tee -a /etc/sysctl.conf
echo "net.ipv4.conf.default.accept_redirects = 0" | sudo tee -a /etc/sysctl.conf
echo "net.ipv4.conf.all.send_redirects = 0" | sudo tee -a /etc/sysctl.conf
echo "net.ipv6.conf.all.accept_redirects = 0" | sudo tee -a /etc/sysctl.conf
echo "kernel.kptr_restrict = 2" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p

# 9. Configure AIDE (file integrity)
sudo aide --init
sudo mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz

# 10. Install and configure fail2ban
sudo dnf install -y fail2ban
sudo systemctl enable fail2ban
sudo systemctl start fail2ban

echo " Enterprise security hardening completed"

```

---

## Step 2: Kubernetes Security Hardening

```python
# kubernetes-security-policies.yaml
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: enterprise-restricted
  annotations:
    seccomp.security.alpha.kubernetes.io/allowedProfileNames: 'runtime/default'
    apparmor.security.beta.kubernetes.io/allowedProfileNames: 'runtime/default'
    seccomp.security.alpha.kubernetes.io/defaultProfileName: 'runtime/default'
spec:
  privileged: false
  allowPrivilegeEscalation: false
  requiredDropCapabilities:
    - ALL
  volumes:
    - 'configMap'
    - 'emptyDir'
    - 'projected'
    - 'secret'
    - 'downwardAPI'
    - 'persistentVolumeClaim'
  hostNetwork: false
  hostIPC: false
  hostPID: false
  runAsUser:
    rule: 'MustRunAsNonRoot'
  seLinux:
    rule: 'RunAsAny'
  fsGroup:
    rule: 'MustRunAs'
    ranges:
      - min: 1
        max: 65535
  readOnlyRootFilesystem: false
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: psp:restricted
rules:
- apiGroups: ['policy']
  resources: ['podsecuritypolicies']
  verbs: ['use']
  resourceNames: ['enterprise-restricted']
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: psp:restricted:default
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: psp:restricted
subjects:
- kind: Group
  name: system:authenticated
  apiGroup: rbac.authorization.k8s.io
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-all
  namespace: default
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-namespace-communication
  namespace: runai
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          name: runai
  egress:
  - to:
    - namespaceSelector:
        matchLabels:
          name: runai
```

---

## Step 3: Run.ai Security Configuration
```python
# runai-enterprise-security.yaml
apiVersion: run.ai/v1
kind: SecurityConfiguration
metadata:
  name: enterprise-security
  namespace: runai
spec:
  # Authentication & Authorization
  authentication:
    type: oidc
    oidc:
      issuer: "https://sso.enterprise.com"
      clientId: "runai-enterprise"
      groupsClaim: "groups"
      usernameClaim: "email"
      
  authorization:
    rbac:
      enabled: true
    projects:
      isolation: strict
      
  # Network Security
  network:
    podSecurityPolicies: true
    networkPolicies: true
    egressRestrictions: true
    allowedEgressCIDRs:
      - "10.0.0.0/8"
      - "192.168.0.0/16"
      
  # Data Security
  data:
    encryption:
      enabled: true
      atRest: true
      inTransit: true
    tokenRotation: 
      enabled: true
      interval: "24h"
      
  # Compliance
  compliance:
    hipaa: true
    soc2: true
    gdpr: true
    audit:
      enabled: true
      retention: "365d"
---
apiVersion: run.ai/v1
kind: Project
metadata:
  name: healthcare-research
  namespace: runai
spec:
  security:
    compliance: 
      hipaa: true
      dataClassification: "PHI"
    networkIsolation: true
    allowedUsers:
      - "healthcare-research@enterprise.com"
    allowedImageRegistries:
      - "registry.enterprise.com/approved-images"
    resourceLimits:
      maxGPUs: 16
      maxMemory: "128Gi"
      allowedGPUTypes: ["A100-80GB", "V100-32GB"]
```

---

## Step 4: Enterprise Compliance Monitoring

```python
# compliance_monitor.py
import json
import yaml
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any
import kubernetes.client
from kubernetes.client.rest import ApiException

class EnterpriseComplianceMonitor:
    def __init__(self, kubeconfig_path: str):
        self.kubeconfig = kubeconfig_path
        self.setup_kubernetes_client()
        self.logger = self._setup_logging()
        
    def setup_kubernetes_client(self):
        """Initialize Kubernetes client"""
        kubernetes.config.load_kube_config(config_file=self.kubeconfig)
        self.core_v1 = kubernetes.client.CoreV1Api()
        self.apps_v1 = kubernetes.client.AppsV1Api()
        self.networking_v1 = kubernetes.client.NetworkingV1Api()
        
    def _setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - [Compliance-Monitor] - %(message)s'
        )
        return logging.getLogger(__name__)
    
    def check_pod_security(self, namespace: str = "all") -> Dict[str, Any]:
        """Check pod security compliance"""
        self.logger.info(f"Checking pod security compliance for namespace: {namespace}")
        
        violations = []
        compliant_pods = 0
        total_pods = 0
        
        try:
            if namespace == "all":
                pods = self.core_v1.list_pod_for_all_namespaces()
            else:
                pods = self.core_v1.list_namespaced_pod(namespace)
                
            for pod in pods.items:
                total_pods += 1
                pod_violations = self._check_pod_security_context(pod)
                
                if not pod_violations:
                    compliant_pods += 1
                else:
                    violations.append({
                        'namespace': pod.metadata.namespace,
                        'pod_name': pod.metadata.name,
                        'violations': pod_violations
                    })
                    
        except ApiException as e:
            self.logger.error(f"Kubernetes API exception: {e}")
            
        compliance_rate = (compliant_pods / total_pods * 100) if total_pods > 0 else 0
        
        return {
            'check_type': 'pod_security',
            'timestamp': datetime.now().isoformat(),
            'summary': {
                'total_pods': total_pods,
                'compliant_pods': compliant_pods,
                'compliance_rate': round(compliance_rate, 2),
                'violations_count': len(violations)
            },
            'violations': violations
        }
    
    def _check_pod_security_context(self, pod) -> List[str]:
        """Check individual pod security context"""
        violations = []
        
        # Check if running as root
        if pod.spec.security_context and pod.spec.security_context.run_as_non_root:
            pass  # Good
        else:
            # Check containers
            for container in pod.spec.containers:
                if not container.security_context or not container.security_context.run_as_non_root:
                    violations.append(f"Container {container.name} may run as root")
        
        # Check privilege escalation
        for container in pod.spec.containers:
            if container.security_context and container.security_context.allow_privilege_escalation:
                violations.append(f"Container {container.name} allows privilege escalation")
        
        # Check privileged mode
        for container in pod.spec.containers:
            if container.security_context and container.security_context.privileged:
                violations.append(f"Container {container.name} runs in privileged mode")
                
        return violations
    
    def check_network_policies(self) -> Dict[str, Any]:
        """Check network policy compliance"""
        self.logger.info("Checking network policy compliance")
        
        violations = []
        namespaces_without_policies = []
        
        try:
            namespaces = self.core_v1.list_namespace()
            
            for namespace in namespaces.items:
                ns_name = namespace.metadata.name
                
                # Skip system namespaces
                if ns_name in ['kube-system', 'kube-public', 'kube-node-lease']:
                    continue
                    
                # Check if namespace has network policies
                policies = self.networking_v1.list_namespaced_network_policy(ns_name)
                
                if len(policies.items) == 0:
                    namespaces_without_policies.append(ns_name)
                    violations.append({
                        'namespace': ns_name,
                        'violation': 'No network policies defined'
                    })
                    
        except ApiException as e:
            self.logger.error(f"Kubernetes API exception: {e}")
            
        return {
            'check_type': 'network_policies',
            'timestamp': datetime.now().isoformat(),
            'summary': {
                'namespaces_without_policies': len(namespaces_without_policies),
                'total_namespaces_checked': len(namespaces.items) - 3  # Exclude system namespaces
            },
            'violations': violations
        }
    
    def check_image_security(self, namespace: str = "all") -> Dict[str, Any]:
        """Check container image security compliance"""
        self.logger.info(f"Checking image security for namespace: {namespace}")
        
        violations = []
        approved_registries = [
            'registry.enterprise.com',
            'nvcr.io/nvidia',
            'docker.io/library'
        ]
        
        try:
            if namespace == "all":
                pods = self.core_v1.list_pod_for_all_namespaces()
            else:
                pods = self.core_v1.list_namespaced_pod(namespace)
                
            for pod in pods.items:
                for container in pod.spec.containers:
                    image = container.image
                    
                    # Check if image is from approved registry
                    if not any(registry in image for registry in approved_registries):
                        violations.append({
                            'namespace': pod.metadata.namespace,
                            'pod_name': pod.metadata.name,
                            'container_name': container.name,
                            'image': image,
                            'violation': 'Image from unapproved registry'
                        })
                    
                    # Check for latest tag
                    if ':latest' in image:
                        violations.append({
                            'namespace': pod.metadata.namespace,
                            'pod_name': pod.metadata.name, 
                            'container_name': container.name,
                            'image': image,
                            'violation': 'Image uses latest tag'
                        })
                        
        except ApiException as e:
            self.logger.error(f"Kubernetes API exception: {e}")
            
        return {
            'check_type': 'image_security',
            'timestamp': datetime.now().isoformat(),
            'summary': {
                'violations_count': len(violations)
            },
            'violations': violations
        }
    
    def generate_compliance_report(self) -> Dict[str, Any]:
        """Generate comprehensive compliance report"""
        self.logger.info("Generating comprehensive compliance report")
        
        reports = {
            'pod_security': self.check_pod_security(),
            'network_policies': self.check_network_policies(),
            'image_security': self.check_image_security(),
            'report_metadata': {
                'generated_at': datetime.now().isoformat(),
                'cluster_name': 'enterprise-hpc-ai-cluster',
                'compliance_standards': ['HIPAA', 'SOC2', 'GDPR']
            }
        }
        
        # Calculate overall compliance score
        total_checks = 0
        passed_checks = 0
        
        for check_type, report in reports.items():
            if check_type == 'report_metadata':
                continue
                
            if 'summary' in report:
                total_checks += 1
                if report['summary'].get('violations_count', 0) == 0:
                    passed_checks += 1
        
        overall_score = (passed_checks / total_checks * 100) if total_checks > 0 else 0
        reports['overall_compliance_score'] = round(overall_score, 2)
        
        # Determine compliance status
        if overall_score >= 90:
            compliance_status = "COMPLIANT"
        elif overall_score >= 70:
            compliance_status = "PARTIALLY_COMPLIANT" 
        else:
            compliance_status = "NON_COMPLIANT"
            
        reports['compliance_status'] = compliance_status
        
        return reports
    
    def save_compliance_report(self, report: Dict[str, Any], output_path: str):
        """Save compliance report to file"""
        filename = f"compliance_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        full_path = f"{output_path}/{filename}"
        
        with open(full_path, 'w') as f:
            json.dump(report, f, indent=2)
        
        self.logger.info(f"Compliance report saved to {full_path}")

# Example usage
if __name__ == "__main__":
    # Initialize compliance monitor
    compliance_monitor = EnterpriseComplianceMonitor('/etc/kubernetes/admin.conf')
    
    # Generate compliance report
    compliance_report = compliance_monitor.generate_compliance_report()
    
    # Save report
    compliance_monitor.save_compliance_report(compliance_report, '/reports/compliance')
    
    print("Compliance Report Summary:")
    print(f"Overall Score: {compliance_report['overall_compliance_score']}%")
    print(f"Status: {compliance_report['compliance_status']}")
    print(f"Pod Security Compliance: {compliance_report['pod_security']['summary']['compliance_rate']}%")
    print(f"Network Policy Violations: {compliance_report['network_policies']['summary']['namespaces_without_policies']}")

```

---

## Step 5: Automated Security Scanning

```python

# security-scanning-pipeline.yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: security-scanning
  namespace: security
spec:
  schedule: "0 2 * * *"  # Daily at 2 AM
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: trivy-scanner
            image: aquasec/trivy:0.40.0
            command:
            - /bin/sh
            - -c
            - |
              # Scan Kubernetes cluster
              trivy k8s --report summary cluster
              
              # Scan Run.ai namespaces
              trivy k8s --namespace runai --format json --output /reports/runai-security-scan.json
              
              # Scan Slurm namespaces  
              trivy k8s --namespace slurm --format json --output /reports/slurm-security-scan.json
            volumeMounts:
            - name: reports
              mountPath: /reports
            - name: kubeconfig
              mountPath: /root/.kube
              readOnly: true
          - name: kube-bench
            image: aquasec/kube-bench:0.6.8
            command:
            - kube-bench
            - --json
            - run
            volumeMounts:
            - name: reports
              mountPath: /reports
            - name: var-lib-kubelet
              mountPath: /var/lib/kubelet
              readOnly: true
            - name: etc-kubernetes
              mountPath: /etc/kubernetes
              readOnly: true
          - name: report-aggregator
            image: python:3.9
            command:
            - python
            - /scripts/aggregate_reports.py
            volumeMounts:
            - name: reports
              mountPath: /reports
            - name: scripts
              mountPath: /scripts
          restartPolicy: OnFailure
          volumes:
          - name: reports
            persistentVolumeClaim:
              claimName: security-reports-pvc
          - name: kubeconfig
            secret:
              secretName: kubeconfig-secret
          - name: var-lib-kubelet
            hostPath:
              path: /var/lib/kubelet
          - name: etc-kubernetes
            hostPath:
              path: /etc/kubernetes
          - name: scripts
            configMap:
              name: security-scripts

```

---


















### Thank you for reading
---

### **AUTHOR'S BACKGROUND**
### Author's Name:  Emmanuel Oyekanlu
```
Skillset:   I have experience spanning several years in data science, developing scalable enterprise data pipelines,
enterprise solution architecture, architecting enterprise systems data and AI applications,
software and AI solution design and deployments, data engineering, high performance computing (GPU, CUDA), machine learning,
NLP, Agentic-AI and LLM applications as well as deploying scalable solutions (apps) on-prem and in the cloud.

I can be reached through: manuelbomi@yahoo.com

Website:  http://emmanueloyekanlu.com/
Publications:  https://scholar.google.com/citations?user=S-jTMfkAAAAJ&hl=en
LinkedIn:  https://www.linkedin.com/in/emmanuel-oyekanlu-6ba98616
Github:  https://github.com/manuelbomi

```
[![Icons](https://skillicons.dev/icons?i=aws,azure,gcp,scala,mongodb,redis,cassandra,kafka,anaconda,matlab,nodejs,django,py,c,anaconda,git,github,mysql,docker,kubernetes&theme=dark)](https://skillicons.dev)

