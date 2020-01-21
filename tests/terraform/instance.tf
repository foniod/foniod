provider "aws" {
  region = "eu-west-1"
}

output "amd64_ip" {
  value = aws_instance.ingraind.public_ip
}

output "arm64_ip" {
  value = aws_instance.ingraind_arm64.public_ip
}

resource "aws_instance" "ingraind" {
  ami           = lookup(local.ec2_ami_map, var.ec2_os_ami)
  instance_type = "t2.micro"
  key_name      = var.ec2_ssh_key_name
  vpc_security_group_ids = [data.aws_security_group.allow_ssh.id]
  subnet_id     = data.aws_subnet.ingraind.id

  availability_zone = "eu-west-1c"
  tags = {
    Name = "ingraind-test"
  }
}

resource "aws_instance" "ingraind_arm64" {
  ami           = lookup(local.ec2_ami_map, var.ec2_os_ami)
  instance_type = "a1.metal"
  key_name      = var.ec2_ssh_key_name
  vpc_security_group_ids = [data.aws_security_group.allow_ssh.id]
  subnet_id     = data.aws_subnet.ingraind.id

  availability_zone = "eu-west-1c"
  tags = {
    Name = "ingraind-arm64-test"
  }
}

resource "null_resource" "provision" {
  # Changes to any instance of the cluster requires re-provisioning
  triggers = {
    instance_ids = aws_instance.ingraind.id
  }

  connection {
    type = "ssh"
    user = lookup(local.ec2_user_map, var.ec2_os_ami)
    host = aws_instance.ingraind.public_ip
    private_key = var.ec2_ssh_private_key
  }

  provisioner "file" {
    source = "config.toml"
    destination = "/tmp/config.toml"
  }

  provisioner "file" {
    source = "ingraind"
    destination = "/tmp/ingraind"
  }

  provisioner "remote-exec" {
    inline = [
      "chmod +x /tmp/ingraind",
      "(sudo env RUST_BACKTRACE=1 RUST_LOG=INFO /tmp/ingraind /tmp/config.toml | grep -v Measurement) &",
      "sleep 3",
      "sudo pkill -9 ingraind",
    ]
  }
}

resource "null_resource" "provision_arm64" {
  # this is techincally just here to delay the exit of terraform until
  # we can verify the VM has booted.

  triggers = {
    instance_ids = aws_instance.ingraind_arm64.id
  }

  connection {
    type = "ssh"
    user = lookup(local.ec2_user_map, var.ec2_os_ami)
    host = aws_instance.ingraind_arm64.public_ip
    private_key = var.ec2_ssh_private_key
  }

  provisioner "file" {
    source = "config.toml"
    destination = "/home/ubuntu/config.toml"
  }

  provisioner "file" {
    source = "provision-arm64.sh"
    destination = "/home/ubuntu/provision.sh"
  }


  provisioner "remote-exec" {
    inline = ["echo connection established"]
  }
}

data "aws_subnet" "ingraind" {
  filter {
    name = "tag:Environment"
    values = ["ingraind-test"]
  }
}

data "aws_security_group" "allow_ssh" {
  filter {
    name = "tag:Environment"
    values = ["ingraind-test"]
  }
}

locals {
  ec2_ami_map = "${map(
    "ubuntu-arm64-1910", "${data.aws_ami.ubuntu-arm64-1910.id}",
    "ubuntu-1804", "${data.aws_ami.ubuntu-1804.id}",
    "ubuntu-1604", "${data.aws_ami.ubuntu-1604.id}",
    "debian-9", "${data.aws_ami.debian-9.id}",
    "centos-7", "${data.aws_ami.centos-7.id}",
    "fedora-31", "${data.aws_ami.fedora-31.id}",
  )}"

  ec2_user_map = "${map(
    "ubuntu-arm64-1910", "ubuntu",
    "ubuntu-1804", "ubuntu",
    "ubuntu-1604", "ubuntu",
    "debian-9", "admin",
    "centos-7", "ec2-user",
    "fedora-31", "fedora",
  )}"
}

variable "ec2_ssh_key_name" {
  type = string
}

variable "ec2_ssh_private_key" {
  type = string
}

variable "ec2_os_ami" {
  type = string
  default = "ubuntu-1804"
}

data "aws_ami" "fedora-31" {
  most_recent = true

  filter {
    name   = "name"
    values = ["Fedora-Cloud-Base-31-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }

  filter {
    name   = "architecture"
    values = ["x86_64"]
  }


  owners = ["125523088429"] # Fedora Cloud
}

data "aws_ami" "debian-9" {
  most_recent = true

  filter {
    name   = "name"
    values = ["debian-stretch-hvm-x86_64-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }

  owners = ["379101102735"] # Debian
}

data "aws_ami" "centos-7" {
  most_recent = true

  filter {
    name   = "product-code"
    values = ["aw0evgkw8e5c1q413zgy5pjce"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }

  owners = ["679593333241"] # Centos.org
}

data "aws_ami" "ubuntu-1804" {
  most_recent = true

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-bionic-18.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }

  owners = ["099720109477"] # Canonical
}

data "aws_ami" "ubuntu-1604" {
  most_recent = true

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-xenial-16.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }

  owners = ["099720109477"] # Canonical
}

data "aws_ami" "ubuntu-arm64-1910" {
  most_recent = true

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-eoan-19.10-arm64-server-*"]
  }

  filter {
    name   = "architecture"
    values = ["arm64"]
  }

  owners = ["099720109477"] # Canonical
}
