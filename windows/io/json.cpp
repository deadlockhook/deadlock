#include "json.h"

using namespace windows;
void io::json_state::set_current_category(secure_string _current_category) {
    atomic::unique_lock<atomic::critical_section> lock(&crit_section);
    current_category = std::move(_current_category);
}

void io::json_state::push_var(secure_string name, bool* pointer) {

    atomic::unique_lock<atomic::critical_section> lock(&crit_section);

    if (!already_exist(current_category + name))
        vec_booleans.emplace_back(pointer, current_category, current_category + name, *pointer);
}

void io::json_state::push_var(secure_string name, int* pointer) {

    atomic::unique_lock<atomic::critical_section> lock(&crit_section);

    if (!already_exist(current_category + name))
        vec_integers.emplace_back(pointer, current_category, current_category + name, *pointer);
}

void io::json_state::push_var(secure_string name, int64_t* pointer) {

    atomic::unique_lock<atomic::critical_section> lock(&crit_section);

    if (!already_exist(current_category + name))
        vec_int64.emplace_back(pointer, current_category, current_category + name, *pointer);
}

void io::json_state::push_var(secure_string name, float* pointer) {

    atomic::unique_lock<atomic::critical_section> lock(&crit_section);

    if (!already_exist(current_category + name))
        vec_floats.emplace_back(pointer, current_category, current_category + name, *pointer);
}

void io::json_state::push_var(secure_string name, secure_string* pointer) {

    atomic::unique_lock<atomic::critical_section> lock(&crit_section);

    if (!already_exist(current_category + name))
        vec_strings.emplace_back(pointer, current_category, current_category + name, *pointer);
}

void io::json_state::clear_state() {

    atomic::unique_lock<atomic::critical_section> lock(&crit_section);

    vec_booleans.clear();
    vec_integers.clear();
    vec_int64.clear();
    vec_floats.clear();
    vec_strings.clear();
}

void io::json_state::reset_state() {

    atomic::unique_lock<atomic::critical_section> lock(&crit_section);

    for (auto& current_item : vec_booleans)
        *current_item.pointer = current_item.default_value;

    for (auto& current_item : vec_integers)
        *current_item.pointer = current_item.default_value;

    for (auto& current_item : vec_int64)
        *current_item.pointer = current_item.default_value;

    for (auto& current_item : vec_floats)
        *current_item.pointer = current_item.default_value;

    for (auto& current_item : vec_strings)
        *current_item.pointer = current_item.default_value;
}

bool io::json_state::already_exist(const secure_string& item_index)
{
    bool ret = already_exist_in_list(vec_booleans, item_index) ||
        already_exist_in_list(vec_integers, item_index) ||
        already_exist_in_list(vec_int64, item_index) ||
        already_exist_in_list(vec_floats, item_index) ||
        already_exist_in_list(vec_strings, item_index);

    return ret;
}

template <typename value_type>
bool  io::json_state::already_exist_in_list(secure_vector<json_item<value_type>>& list, const secure_string& item_index) {
    for (auto& current : list)
        if (current.item_id == item_index)
            return true;

    return false;
}

void io::json_state::remove_elements_by_category_name(secure_string _category)
{
    atomic::unique_lock<atomic::critical_section> lock(&crit_section);

    auto remove_by_category = [&](auto& list) {
        list.erase(std::remove_if(list.begin(), list.end(),
            [&_category](const auto& item) { return item.category == _category; }),
            list.end());
        };

    remove_by_category(vec_booleans);
    remove_by_category(vec_integers);
    remove_by_category(vec_int64);
    remove_by_category(vec_floats);
    remove_by_category(vec_strings);
}

secure_string io::json_state::convert_json_state_to_json_string()
{
    atomic::unique_lock<atomic::critical_section> lock(&crit_section);

    Document doc;
    doc.SetObject();

    Document::AllocatorType& allocator = doc.GetAllocator();

    for (auto& current_item : vec_booleans)
    {
        doc.AddMember(rapidjson::Value(current_item.item_id.c_str(), allocator),
            rapidjson::Value().SetBool(*current_item.pointer), allocator);
    }

    for (auto& current_item : vec_integers)
    {
        doc.AddMember(rapidjson::Value(current_item.item_id.c_str(), allocator),
            rapidjson::Value().SetInt(*current_item.pointer), allocator);
    }

    for (auto& current_item : vec_int64)
    {
        doc.AddMember(rapidjson::Value(current_item.item_id.c_str(), allocator),
            rapidjson::Value().SetInt64(*current_item.pointer), allocator);
    }

    for (auto& current_item : vec_floats)
    {
        doc.AddMember(rapidjson::Value(current_item.item_id.c_str(), allocator),
            rapidjson::Value().SetFloat(*current_item.pointer), allocator);
    }

    for (auto& current_item : vec_strings)
    {
        doc.AddMember(rapidjson::Value(current_item.item_id.c_str(), allocator),
            rapidjson::Value(current_item.pointer->c_str(), allocator), allocator);
    }

    rapidjson::StringBuffer buffer;
    rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
    doc.Accept(writer);

    return buffer.GetString();
}

void io::json_state::convert_json_string_to_json_state(const secure_string& json_string)
{
    Document parsed_document;
    if (parsed_document.Parse(json_string.c_str()).HasParseError())
        return;

    atomic::unique_lock<atomic::critical_section> lock(&crit_section);

    for (auto& current_item : vec_booleans)
    {
        if (parsed_document.HasMember(current_item.item_id.c_str()) &&
            parsed_document[current_item.item_id.c_str()].IsBool())
        {
            *current_item.pointer = parsed_document[current_item.item_id.c_str()].GetBool();
        }
    }

    for (auto& current_item : vec_integers)
    {
        if (parsed_document.HasMember(current_item.item_id.c_str()) &&
            parsed_document[current_item.item_id.c_str()].IsInt())
        {
            *current_item.pointer = parsed_document[current_item.item_id.c_str()].GetInt();
        }
    }

    for (auto& current_item : vec_int64)
    {
        if (parsed_document.HasMember(current_item.item_id.c_str()) &&
            parsed_document[current_item.item_id.c_str()].IsInt64())
        {
            *current_item.pointer = parsed_document[current_item.item_id.c_str()].GetInt64();
        }
    }

    for (auto& current_item : vec_floats)
    {
        if (parsed_document.HasMember(current_item.item_id.c_str()) &&
            parsed_document[current_item.item_id.c_str()].IsFloat())
        {
            *current_item.pointer = parsed_document[current_item.item_id.c_str()].GetFloat();
        }
    }

    for (auto& current_item : vec_strings)
    {
        if (parsed_document.HasMember(current_item.item_id.c_str()) &&
            parsed_document[current_item.item_id.c_str()].IsString())
        {
            *current_item.pointer = parsed_document[current_item.item_id.c_str()].GetString();
        }
    }
}