variable "account" {
  default = ""
}

variable "arena" {
  default = "core"
}

variable "region" {
  default = "us-west-2"
}

variable "environment" {
  default = "stage"
}

variable "service_name" {
  default = "kubernetes"
}

variable "nubis_sudo_groups" {
  default = "nubis_global_admins"
}

variable "ami" {}
