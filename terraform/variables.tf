variable "vpc_name" {
  description = "Name for the VPC"
  type        = string
  default     = "shiun-k8s-summit-vpc"
}

variable "instance_name" {
  description = "Name tag for the EC2 instance"
  type        = string
  default     = "shiun-k8s-summit-instance"
}

variable "instance_type" {
  description = "Instance type for the EC2 instance"
  type        = string
  default     = "m6i.large"

}

variable "ami_id" {
  description = "AMI ID for the EC2 instance"
  type        = string
  default     = "ami-07b3f199a3bed006a" # Ubuntu Server 22.04 LTS (HVM),EBS General Purpose (SSD)

}
