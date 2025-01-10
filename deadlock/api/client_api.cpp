#include "client_api.h"


net_message get_net_send_message_buffer()
{
	//handle reports
	//connection messages
	//timeouts
	return net_message(0, 0, 0, 0);
}


void post_net_send_message_buffer()
{
	//clear all the sent reports
}

void on_net_receive_message_buffer(net_message msg)
{
	//verify header
	//if recieved from the server mini client use it for taking actions
}