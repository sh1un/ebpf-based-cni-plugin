output "instance_id" {
  description = "The ID of the EC2 instance"
  value       = aws_instance.ubuntu.id
}

output "public_ip" {
  description = "The public IP address of the EC2 instance"
  value       = aws_instance.ubuntu.public_ip
}

output "private_ip" {
  description = "The private IP address of the EC2 instance"
  value       = aws_instance.ubuntu.private_ip
}
