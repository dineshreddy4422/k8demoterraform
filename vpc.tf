terraform {
  backend "s3" {
    bucket = "backend-tf"
    key    = "test/k8s/cluster.tfstate"
    region = "us-east-1"
  }
}

resource "aws_vpc" "cluster" {
  cidr_block = "10.0.0.0/16"

  tags = "${merge(
    map(
     "Name", "terraform-eks-${var.cluster_name}",
     "kubernetes.io/cluster/${var.cluster_name}", "shared",
    ),
    local.common_tags
  )}"
}

resource "aws_subnet" "cluster" {
  count = 2

  availability_zone = "${var.availability_zones[count.index]}"
  cidr_block        = "10.0.${count.index}.0/24"
  vpc_id            = "${aws_vpc.cluster.id}"

  tags = "${merge(
    map(
     "Name", "terraform-eks-${var.cluster_name}",
     "kubernetes.io/cluster/${var.cluster_name}", "shared",
    ),
    local.common_tags
  )}"
}

resource "aws_internet_gateway" "cluster" {
  vpc_id = "${aws_vpc.cluster.id}"

  tags = "${merge(
    map("Name", "terraform-eks-${var.cluster_name}"),
    local.common_tags
  )}"
}

resource "aws_route_table" "cluster" {
  vpc_id = "${aws_vpc.cluster.id}"

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = "${aws_internet_gateway.cluster.id}"
  }
}

resource "aws_route_table_association" "eks" {
  count = 2

  subnet_id      = "${aws_subnet.cluster.*.id[count.index]}"
  route_table_id = "${aws_route_table.cluster.id}"
}
