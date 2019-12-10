terraform {
  backend "s3" {
    bucket         = "redsift-labs-terraform-states"
    dynamodb_table = "terraform-locks"
    region         = "eu-west-2"
    key            = "ingraind-test"
  }
}

provider "aws" {
  region = "eu-west-2"
}

resource "aws_vpc" "ingraind" {
  cidr_block = "172.16.0.0/16"

  tags = {
    Environment = "ingraind-test"
  }
}

resource "aws_internet_gateway" "gw" {
  vpc_id = "${aws_vpc.ingraind.id}"

  tags = {
    Environment = "ingraind-test"
  }
}

resource "aws_subnet" "ingraind" {
  vpc_id            = "${aws_vpc.ingraind.id}"
  cidr_block        = "172.16.10.0/24"
  map_public_ip_on_launch = true

  tags = {
    Environment = "ingraind-test"
  }
}

resource "aws_route_table" "internet" {
  vpc_id            = "${aws_vpc.ingraind.id}"

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = "${aws_internet_gateway.gw.id}"
  }

  tags = {
    Environment = "ingraind-test"
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
    Environment = "ingraind-test"
  }
}
