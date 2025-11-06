# Infrastructure Deployment and Web Application Setup

This repository contains the configuration files and automation scripts to deploy an AWS EC2 instance, provision it with necessary software (Docker, Docker Compose, Nginx), and deploy a basic Nginx-based web application using a Docker container.

The deployment process is fully automated using a **GitHub Actions workflow**.

---

# Components

This setup uses the following core components:

* **Terraform:** To define and provision the AWS infrastructure (EC2 Instance, Security Group, Key Pair).
* **GitHub Actions:** To automate the entire deployment pipeline (CI/CD).
* **Ansible:** To configure the deployed EC2 instance, install prerequisites, and run the Docker application.
* **Dockerfile:** Defines a simple web application using an `nginx:alpine` image.
* **Ansible Playbook (`deploy.yml`):** Used to provision the server.

---

## Deployment Workflow

The infrastructure deployment is managed by the GitHub Actions workflow defined in `.github/workflows/deploy-infrastructure.yml` (based on the provided YAML).

The workflow is triggered on pushes and pull requests to the `main` branch.

### Workflow Steps at a Glance:

1.  **Checkout Code:** Clones the repository.
2.  **Setup Terraform:** Installs the required Terraform version (`1.5.0`).
3.  **Install Ansible:** Installs Ansible for provisioning.
4.  **Configure AWS Credentials:** Uses `aws-actions/configure-aws-credentials` to authenticate with AWS using secrets.
5.  **Setup SSH Keys:** Configures the private and public SSH keys needed for Ansible to connect to the new EC2 instance.
6.  **Terraform Init, Validate, & Plan:** Prepares the Terraform workspace and verifies the configuration.
7.  **Terraform Apply:** **Only runs on a `push` event to the `main` branch.** This provisions the EC2 instance.
8.  **Ansible Provisioning:** The EC2 instance resource includes a `provisioner "local-exec"` block that executes the Ansible playbook (`deploy.yml`) immediately after the instance is created.
    * The playbook installs Docker, Docker Compose, Nginx, configures Nginx as a reverse proxy, and deploys the containerized web app.
9.  **Upload Terraform state:** Saves the `terraform.tfstate` files as a GitHub Artifact for future runs.

---

## Infrastructure and Provisioning Details

### Terraform (`main.tf` equivalent)

* **EC2 Instance:** An Amazon Linux 2 AMI (`ami-0c5204531f799e0c6`) with a `t3.micro` instance type is used.
* **Security Group:** Opens ports **80 (HTTP), 443 (HTTPS), and 22 (SSH)** to the world (`0.0.0.0/0`).
* **Key Pair:** A new key pair is created and used for the instance.
* **Post-creation:** The Ansible playbook is executed using a `local-exec` provisioner from the GitHub runner, connecting to the new EC2 instance's public IP using the provisioned SSH key.

### Ansible Playbook (`deploy.yml`)

The playbook handles server setup:

* Installs **Python 3.8** (required for some Ansible modules).
* Installs and starts **Docker**.
* Installs the **Docker Compose binary** (`v2.20.0`).
* Adds the `ec2-user` to the `docker` group.
* Installs and restarts **Nginx**.
* Configures Nginx to act as a **reverse proxy** from port 80 to the Docker Compose application running on port 8080.
* Copies the web application files (`myPage/`) to the server.
* Runs **Docker Compose** to build and start the web application container.

### Web Application (`Dockerfile` equivalent)

The application is a simple **Nginx container** that copies the local `index.html` file into the Nginx default directory.

---

## Required GitHub Secrets

The GitHub Actions workflow relies on the following repository secrets for successful execution:

| Secret Name | Description |
| :--- | :--- |
| `AWS_ACCESS_KEY_ID` | Your AWS IAM user's access key ID. |
| `AWS_SECRET_ACCESS_KEY` | Your AWS IAM user's secret access key. |
| `SSH_PRIVATE_KEY` | The private key content for the EC2 instance. |
| `SSH_PUBLIC_KEY` | The public key content for the EC2 instance. |

---

## Next Steps

To make this setup runnable, ensure you have:

1.  Defined the required **GitHub Secrets**.
2.  Created the Ansible playbook file (`deploy.yml`).
3.  Created the Dockerfile and the associated files (`index.html`, `myPage/`).
4.  Committed all files and pushed to the `main` branch.