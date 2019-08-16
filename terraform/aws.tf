locals {
  ec2_ami_map = "${map(
    "ubuntu-1804", "${data.aws_ami.ubuntu-1804.id}",
    "ubuntu-1604", "${data.aws_ami.ubuntu-1604.id}",
    "debian-9", "${data.aws_ami.debian-9.id}",
    "centos-7", "${data.aws_ami.centos-7.id}"
  )}"

  ec2_user_map = "${map(
    "ubuntu-1804", "ubuntu",
    "ubuntu-1904", "ubuntu",
    "debian-9", "admin",
    "centos-7", "ec2-user"
  )}"
}

provider "aws" {
  region = "eu-west-2"
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

resource "aws_vpc" "ingraind" {
  cidr_block = "172.16.0.0/16"

  tags = {
    Name = "IngrainD test matrix"
  }
}

resource "aws_internet_gateway" "gw" {
  vpc_id = "${aws_vpc.ingraind.id}"

  tags = {
    Name = "IngrainD test matrix"
  }
}

resource "aws_subnet" "ingraind" {
  vpc_id            = "${aws_vpc.ingraind.id}"
  cidr_block        = "172.16.10.0/24"
  map_public_ip_on_launch = true

  tags = {
    Name = "IngrainD test matrix"
  }
}

resource "aws_route_table" "internet" {
  vpc_id            = "${aws_vpc.ingraind.id}"

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = "${aws_internet_gateway.gw.id}"
  }

  tags = {
    Name = "IngrainD test matrix"
  }
}

resource "aws_route_table_association" "a" {
  subnet_id      = "${aws_subnet.ingraind.id}"
  route_table_id = "${aws_route_table.internet.id}"
}

resource "aws_security_group" "allow_ssh" {
  vpc_id = "${aws_vpc.ingraind.id}"

  ingress {
    protocol  = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    from_port = 22
    to_port   = 22
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "IngrainD test matrix"
  }
}

resource "aws_instance" "ingraind" {
  ami           = "${lookup(local.ec2_ami_map, var.ec2_os_ami)}"
  instance_type = "t2.micro"
  key_name      = "${var.ec2_ssh_key_name}"
  vpc_security_group_ids = ["${aws_security_group.allow_ssh.id}"]
  subnet_id     = "${aws_subnet.ingraind.id}"

  tags = {
    Name = "IngrainD test instance"
  }
}

resource "null_resource" "provision" {
  # Changes to any instance of the cluster requires re-provisioning
  triggers = {
    instance_ids = "${aws_instance.ingraind.id}"
  }

  connection {
    type = "ssh"
    user = "${lookup(local.ec2_user_map, var.ec2_os_ami)}"
    host = "${aws_instance.ingraind.public_ip}"
    private_key = "${var.ec2_ssh_private_key}"
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
      "/tmp/ingraind /tmp/config.toml",
    ]
  }
}
