terraform {
  required_version = ">= 1.5.0"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
  zone    = var.zone
}

# 1) VPC Network
resource "google_compute_network" "ids_vpc" {
  name                    = "ids-vpc"
  auto_create_subnetworks = true
}

# 2) Firewall rule to allow SSH + HTTP/8080
resource "google_compute_firewall" "ids_firewall" {
  name    = "ids-allow-ssh-http"
  network = google_compute_network.ids_vpc.name

  allow {
    protocol = "tcp"
    ports    = ["22", "80", "8080"]
  }

  source_ranges = ["0.0.0.0/0"]
}

# 3) Service account for the VM
resource "google_service_account" "ids_sa" {
  account_id   = "ids-vm-sa"
  display_name = "IDS VM Service Account"
}

# 4) Give that SA access to the log bucket
resource "google_storage_bucket_iam_member" "ids_sa_writer" {
  bucket = var.log_bucket
  role   = "roles/storage.objectAdmin"
  member = "serviceAccount:${google_service_account.ids_sa.email}"
}

# 5) Compute Engine VM for the IDS agent / generator
resource "google_compute_instance" "ids_vm" {
  name         = "ids-gce-vm"
  machine_type = "e2-standard-2"
  zone         = var.zone

  boot_disk {
    initialize_params {
      image = "projects/debian-cloud/global/images/family/debian-11"
    }
  }

  network_interface {
    network = google_compute_network.ids_vpc.id

    access_config {
      # ephemeral public IP
    }
  }

  # Use your startup script to install deps, clone repo, run agent
  metadata_startup_script = file("../deployment/gce_startup.sh")

  service_account {
    email  = google_service_account.ids_sa.email
    scopes = ["https://www.googleapis.com/auth/cloud-platform"]
  }

  tags = ["ids-vm"]
}
