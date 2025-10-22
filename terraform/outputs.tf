output "master_instance_id" {
  description = "The ID of the master EC2 instance"
  value       = aws_instance.master.id
}

output "master_public_ip" {
  description = "The public IP address of the master EC2 instance"
  value       = aws_instance.master.public_ip
}

output "master_private_ip" {
  description = "The private IP address of the master EC2 instance"
  value       = aws_instance.master.private_ip
}

output "worker_instance_ids" {
  description = "The IDs of the worker EC2 instances"
  value       = aws_instance.worker[*].id
}

output "worker_public_ips" {
  description = "The public IP addresses of the worker EC2 instances"
  value       = aws_instance.worker[*].public_ip
}

output "worker_private_ips" {
  description = "The private IP addresses of the worker EC2 instances"
  value       = aws_instance.worker[*].private_ip
}
