#pragma once

struct net_message {
	bool valid = false;
	void* buffer = nullptr;
	size_t size_of_buffer = 0;
	bool has_next_message = false;
};

extern _declspec(dllexport) net_message get_net_send_message_buffer();
extern _declspec(dllexport) void post_net_send_message_buffer();

extern _declspec(dllexport) void on_net_receive_message_buffer(net_message msg); //probably not needed since we dont have to receieve any messages from the game server
