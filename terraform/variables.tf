variable "vpc_name" {
  description = "Name for the VPC"
  type        = string
  default     = "shiun-k8s-summit-vpc"
}

variable "master_instance_name" {
  description = "Name tag for the master EC2 instance"
  type        = string
  default     = "shiun-k8s-summit-master"
}

variable "worker_instance_name" {
  description = "Name tag for the worker EC2 instances"
  type        = string
  default     = "shiun-k8s-summit-worker"
}

variable "worker_count" {
  description = "Number of worker instances"
  type        = number
  default     = 2
}

variable "volume_size" {
  description = "EBS volume size for EC2 instances"
  type        = number
  default     = 30
}

variable "instance_type" {
  description = "Instance type for the EC2 instance"
  type        = string
  default     = "m6i.large"

}

variable "ami_id" {
  description = "AMI ID for the EC2 instance"
  type        = string
  default     = "ami-0a71a0b9c988d5e5e" # Ubuntu Server 24.04 LTS (HVM),EBS General Purpose (SSD) Volume Type. Support available from Canonical (http://www.ubuntu.com/cloud/services).
}
