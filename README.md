# ☁️ Cloud-Based Intrusion Detection System Using Google App Engine and Compute Engine

![GitHub last commit](https://img.shields.io/github/last-commit/your-username/cloud-ids)
![Python](https://img.shields.io/badge/Python-3.10+-blue?logo=python)
![Google Cloud](https://img.shields.io/badge/Google%20Cloud-Platform-orange?logo=googlecloud)
![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)
![Status](https://img.shields.io/badge/Status-In%20Progress-yellow)

---

## 🚀 Quick Deploy
Deploy instantly to your Google Cloud account using App Engine:

[![Deploy to Google Cloud](https://deploy.cloud.run/button.svg)](https://deploy.cloud.run)

---

## 📄 Abstract
This project proposes a **cloud-based Intrusion Detection System (IDS)** deployed on **Google Cloud Platform (GCP)** using two methods:

- **Google App Engine (PaaS)**
- **Google Compute Engine (IaaS)**

The main objective is to evaluate whether App Engine’s **automatic scaling** can handle fluctuating network traffic more efficiently and cost-effectively than a fixed virtual machine on Compute Engine—while maintaining consistent detection accuracy. The system analyzes simulated network logs to detect intrusions using detection logic and leverages GCP tools such as **Cloud Monitoring**, **Cloud Logging**, and **VPCs**. This project applies key cloud computing concepts including **virtualization, scalability, and managed services** in a cybersecurity context.

---

## 📘 1. Project Overview
Cloud computing allows the deployment of scalable, reliable, and cost-effective applications without managing physical infrastructure. Intrusion Detection Systems (IDS) are essential for detecting and analyzing malicious activity in networks. However, traditional on-premise or static VM-based IDS deployments suffer from **high idle costs** and **poor scalability**. This project compares **App Engine (PaaS)** vs **Compute Engine (IaaS)** for deploying an IDS, focusing on scalability, cost, and performance trade-offs.

### Originality
While many studies focus on detection algorithms, few compare the **infrastructure-level performance** of cloud-based IDS systems. This project bridges that gap by testing both deployment methods side by side under simulated network traffic.

### Research Question
> Can an IDS deployed on Google App Engine automatically scale to handle variable network traffic more efficiently than a fixed virtual machine on Google Compute Engine, while maintaining consistent detection accuracy?

---

## 📚 2. Literature Review
Prior research shows:
- On-site IDS solutions struggle with **scalability** and **operational cost**.  
- Cloud-hosted IDS systems enable **elastic scaling** but require more complex configurations.  
- App Engine and Compute Engine offer a trade-off between automation and control.

This project expands on those findings by implementing both models, recording **CPU utilization**, **latency**, and **cost**, and analyzing their effectiveness under identical workloads.

---

## 🎯 3. Hypothesis and Objectives

### Hypothesis
An IDS deployed on **Google App Engine** will **auto-scale efficiently**, resulting in lower idle-time costs while maintaining comparable accuracy to a static Compute Engine deployment.

### SMART Objectives
1. Deploy identical IDS applications on both GCE and GAE within two weeks.  
2. Simulate variable network traffic to test scaling behavior.  
3. Collect metrics on CPU, latency, and operational cost.  
4. Verify accuracy within ±1% between both deployments.  
5. Visualize results in Cloud Monitoring and summarize findings.

---

## ⚙️ 4. Methodology

### Cloud Services Used
| Service | Purpose |
|----------|----------|
| **Google Compute Engine (GCE)** | Fixed VM baseline for IDS testing |
| **Google App Engine (GAE)** | Auto-scaling managed deployment |
| **Google Cloud Storage (GCS)** | Stores synthetic network logs |
| **Virtual Private Cloud (VPC)** | Isolated network with firewall rules |
| **Cloud Monitoring & Logging** | Tracks performance metrics and cost |

### System Architecture
[Traffic Generator] --> [App Engine IDS]
↘︎ [Compute Engine IDS]
↘︎ [Cloud Storage + Monitoring]

### Data Management
- Traffic logs stored in GCS  
- IDS scans logs for suspicious activity (e.g., failed logins, SQL injection)  
- Access secured using IAM roles and encryption  

### Implementation Plan
| Week | Task |
|------|------|
| 1–2 | Configure environments, upload datasets to GCS |
| 3 | Deploy IDS on GCE and GAE using `app.yaml` |
| 4 | Simulate network traffic and log performance |
| 5 | Analyze CPU, latency, and cost data |
| 6 | Build visualization dashboards and final report |

---

## 🗣️ 5. Communication Plan
- Weekly **in-person meetings**
- **Discord** for daily updates
- **GitHub** for version control and documentation
- **Final presentation and report** for dissemination

---

## 🧠 6. Researcher Preparedness
**Skills:** Python, Google Cloud CLI, Linux administration, YAML configuration, and GCP deployment (GCE, GAE, GKE).  
**Course Connection:** Builds on cloud labs from Weeks 2–6 in the Cloud Computing course.

---

## 🧩 7. Training Needs
- Learn Cloud Monitoring dashboards and billing exports  
- Refine App Engine scaling configs (`app.yaml`)  
- Practice cost reporting via **Billing Export to BigQuery**

---

## 🔒 8. Ethical Considerations
- Only **synthetic data** used — no private or personal info  
- Access managed via **IAM least privilege** and encryption  
- Minimize resource use via App Engine’s **scale-to-zero**  
- Cost transparency maintained via billing reports  

---

## ✅ 9. Summary and Conclusions
This project integrates multiple cloud concepts — **virtualization**, **scalability**, and **elastic computing** — into a real cybersecurity use case. By comparing App Engine and Compute Engine, it aims to confirm that **managed PaaS environments can maintain performance with reduced costs**.

**Expected Outcome:**  
App Engine will achieve comparable IDS accuracy while **reducing idle-time and manual overhead**, validating the **PaaS model’s efficiency** in cloud-based security systems.

---

## 📖 10. References
1. Yu-Sung Wu, B. Foo, Y. Mei, and S. Bagchi, “Collaborative Intrusion Detection System (CIDS),” *ACSAC 2003*.  
2. Sergi Belda Garcia, “Viability of Cloud Hosting Solutions,” *2025*.  
3. J. Smith et al., “Comparing Serverless and VM Deployments for Web Apps,” *IEEE Cloud Computing, 2022*.  
4. S. Patel, “Cloud-Based Intrusion Detection: A Review,” *Journal of Cybersecurity Research, 2023*.

---

## 🚀 How to Run 
1. Clone the repository:  
   ```bash
   git clone https://github.com/<your-username>/cloud-ids.git
   cd cloud-ids
   
2. Deploy to Compute Engine:
   gcloud compute instances create ids-vm \
    --image-family=debian-12 \
    --image-project=debian-cloud \
    --metadata-from-file startup-script=compute_engine/startup.sh

3. Deploy to App Engine:
   cd appengine
   gcloud app deploy app.yaml

4. Simulate traffic:
   python traffic_simulator/simulate_traffic.py

   
