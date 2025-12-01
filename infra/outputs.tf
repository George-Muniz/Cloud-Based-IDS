output "ids_vm_external_ip" {
  description = "External IP address of the IDS GCE VM"
  value       = google_compute_instance.ids_vm.network_interface[0].access_config[0].nat_ip
}

output "ids_vm_name" {
  description = "Name of the IDS GCE VM"
  value       = google_compute_instance.ids_vm.name
}
