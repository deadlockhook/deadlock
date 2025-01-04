#pragma once

#include "../crt/crt.h"
#include "../crt/sec_string.h"
#include "../crt/sec_vector.h"
#include "../threading/atomic.h"

#include "../thirdparty/rapidjson/document.h"
#include "../thirdparty/rapidjson/pointer.h"
#include "../thirdparty/rapidjson/stringbuffer.h"
#include "../thirdparty/rapidjson/writer.h"
using namespace rapidjson;

namespace io
{
	template <typename value_type>
	struct json_item {
		value_type* pointer;
		secure_string category;
		secure_string item_id;
		value_type default_value;
	};

	class json_state
	{
	public:
		void set_current_category(secure_string _current_category);
		void push_var(secure_string name, bool* pointer);
		void push_var(secure_string name, int* pointer);
		void push_var(secure_string name, int64_t* pointer);
		void push_var(secure_string name, float* pointer);
		void push_var(secure_string name, secure_string* pointer);
		void remove_elements_by_category_name(secure_string _category);
		secure_string convert_json_state_to_json_string();
		void convert_json_string_to_json_state(const secure_string& json_string);
		void clear_state();
		void reset_state();
	private:
		bool already_exist(const secure_string& item_index);
		template <typename value_type>
		bool already_exist_in_list(secure_vector<json_item<value_type>>& list, const secure_string& item_index);
	private:
		secure_string current_category;
		secure_vector<json_item<bool>> vec_booleans;
		secure_vector<json_item<int>> vec_integers;
		secure_vector<json_item<int64_t>> vec_int64;
		secure_vector<json_item<float>> vec_floats;
		secure_vector<json_item<secure_string>> vec_strings;
		atomic::critical_section crit_section;
	};
}
