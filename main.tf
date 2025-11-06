provider "aws" {
    region = "us-west-2"
  
}


resource "aws_security_group" "micheal_security_group" {
     ingress {
    from_port = 80
    to_port = 80
    protocol = "tcp"
    cidr_blocks = ["0.0.0.0/0"]//allow http from anywhere
}
  ingress {
    from_port = 22
    to_port = 22
    protocol = "tcp"
    cidr_blocks = ["0.0.0.0/0"]//allow ssh from anywhere
}
 ingress {
    from_port = 443
    to_port = 443
    protocol = "tcp"
    cidr_blocks = ["0.0.0.0/0"]//allow https from anywhere
}
    egress {
        from_port = 0
        to_port =  0
        protocol = -1
        cidr_blocks = ["0.0.0.0/0"]//allow all outgoing traffic
    } 
}

variable "key_name" {
    type = string
    default = "micheal_key"
}

resource "aws_key_pair" "micheal_key" {
    key_name = var.key_name
    public_key = file("id_rsa.pub")
  
}
resource "aws_instance" "micheal_server" {
    ami = "ami-0c5204531f799e0c6"
    instance_type = "t3.micro"
    security_groups = [aws_security_group.micheal_security_group.name]
    key_name = aws_key_pair.micheal_key.key_name
    tags = {
        Name = "micheal_server"
    }
    
    # provisioner "local-exec" {
    #     command = "sleep 30 && ANSIBLE_HOST_KEY_CHECKING=False ansible-playbook -i '${self.public_ip},' -u ec2-user --private-key /home/Osayande/.ssh/id_rsa deploy.yml"
    # }

     provisioner "local-exec" {
        command = "sleep 30 && ANSIBLE_HOST_KEY_CHECKING=False ansible-playbook -i '${self.public_ip},' -u ec2-user --private-key id_rsa deploy.yml"
    }
}
output "instance_public_ip" {
    value = aws_instance.micheal_server.public_ip
  
}