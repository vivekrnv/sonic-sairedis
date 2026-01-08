#include "FlowDump.h"

#include "meta/sai_serialize.h"
#include "meta/SaiAttributeList.h"

#include "swss/logger.h"

#include <sstream>
#include <iomanip>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <cstring>

namespace syncd
{


    FlowDumpSerializer& FlowDumpSerializer::getInstance()
    {
        static FlowDumpSerializer instance;
        return instance;
    }

    nlohmann::json FlowDumpSerializer::serializeAttributeValue(
            _In_ const sai_attribute_t& attr,
            _In_ const sai_attr_metadata_t* meta)
    {
        SWSS_LOG_ENTER();

        if (meta == nullptr)
        {
            return nlohmann::json();
        }

        // Serialize attribute value based on its type
        switch (meta->attrvaluetype)
        {
            case SAI_ATTR_VALUE_TYPE_INT32:
                if (meta->enummetadata != nullptr)
                {
                    // For enums, use the numeric value
                    return attr.value.s32;
                }
                return attr.value.s32;

            case SAI_ATTR_VALUE_TYPE_UINT32:
                return attr.value.u32;

            case SAI_ATTR_VALUE_TYPE_UINT16:
                return attr.value.u16;

            case SAI_ATTR_VALUE_TYPE_UINT8:
                return attr.value.u8;

            case SAI_ATTR_VALUE_TYPE_BOOL:
                return attr.value.booldata;

            case SAI_ATTR_VALUE_TYPE_MAC:
                return sai_serialize_mac(attr.value.mac);

            case SAI_ATTR_VALUE_TYPE_IP_ADDRESS:
                return sai_serialize_ip_address(attr.value.ipaddr);

            case SAI_ATTR_VALUE_TYPE_IPV4:
                // Convert IPv4 to string format (use sai_serialize_attr_value for proper serialization)
                {
                    sai_ip_address_t ip_addr;
                    ip_addr.addr_family = SAI_IP_ADDR_FAMILY_IPV4;
                    ip_addr.addr.ip4 = attr.value.ip4;
                    return sai_serialize_ip_address(ip_addr);
                }

            case SAI_ATTR_VALUE_TYPE_IPV6:
                return sai_serialize_ipv6(attr.value.ip6);

            case SAI_ATTR_VALUE_TYPE_IP_PREFIX:
                return sai_serialize_ip_prefix(attr.value.ipprefix);

            case SAI_ATTR_VALUE_TYPE_UINT64:
                return attr.value.u64;

            case SAI_ATTR_VALUE_TYPE_INT64:
                return attr.value.s64;

            case SAI_ATTR_VALUE_TYPE_CHARDATA:
                return std::string(attr.value.chardata);

            default:
                // For other types, serialize to string
                std::string attr_value = sai_serialize_attr_value(*meta, attr, false);
                return attr_value;
        }
    }

    nlohmann::json FlowDumpSerializer::serializeFlowEntryToJson(
            _In_ const sai_flow_bulk_get_session_event_data_t& event_data)
    {
        SWSS_LOG_ENTER();

        nlohmann::json json_line;

        // Add key fields with shortened names (as per HLD spec)
        const sai_flow_entry_t& flow_entry = event_data.flow_entry;
        json_line["em"] = sai_serialize_mac(flow_entry.eni_mac);
        json_line["vn"] = flow_entry.vnet_id;
        json_line["pr"] = flow_entry.ip_proto;
        json_line["si"] = sai_serialize_ip_address(flow_entry.src_ip);
        json_line["di"] = sai_serialize_ip_address(flow_entry.dst_ip);
        json_line["sp"] = flow_entry.src_port;
        json_line["dp"] = flow_entry.dst_port;

        // Add attributes as numeric keys (enum IDs)
        if (event_data.attr != nullptr && event_data.attr_count > 0)
        {
            for (uint32_t j = 0; j < event_data.attr_count; ++j)
            {
                const sai_attribute_t& attr = event_data.attr[j];
                auto meta = sai_metadata_get_attr_metadata(static_cast<sai_object_type_t>(SAI_OBJECT_TYPE_FLOW_ENTRY), attr.id);
                if (meta != nullptr)
                {
                    // Use attribute ID as numeric key
                    json_line[std::to_string(attr.id)] = serializeAttributeValue(attr, meta);
                }
            }
        }

        return json_line;
    }

    FlowDumpDataPtr FlowDumpSerializer::serializeToJsonLines(
            _In_ sai_object_id_t flow_bulk_session_id,
            _In_ uint32_t count,
            _In_ const sai_flow_bulk_get_session_event_data_t *data)
    {
        SWSS_LOG_ENTER();

        if (data == nullptr)
        {
            return nullptr;
        }

        FlowDumpDataPtr flow_dump_data = nullptr;

        for (uint32_t i = 0; i < count; ++i)
        {
            if (data[i].event_type == SAI_FLOW_BULK_GET_SESSION_EVENT_FLOW_ENTRY)
            {
                if (flow_dump_data == nullptr)
                {
                    flow_dump_data = std::make_shared<FlowDumpData>();
                }
                // Convert flow_entry to JSON
                nlohmann::json json_line = serializeFlowEntryToJson(data[i]);
                flow_dump_data->json_lines.push_back(json_line);
            }
        }

        return flow_dump_data;
    }

    FlowDumpWriter::FlowDumpWriter() :
        m_base_path(DEFAULT_BASE_PATH)
    {
    }

    FlowDumpWriter& FlowDumpWriter::getInstance()
    {
        static FlowDumpWriter instance;
        return instance;
    }

    FlowDumpWriter::~FlowDumpWriter()
    {
        SWSS_LOG_ENTER();
    }

    std::string FlowDumpWriter::getFilePath(
            _In_ sai_object_id_t flow_bulk_session_vid) const
    {
        SWSS_LOG_ENTER();

        // Format: <base_path>/flow_dump_<VID>.jsonl.gz
        // VID format: 0xXXXXX (hexadecimal)
        std::ostringstream oss;
        oss << m_base_path << "flow_dump_0x" 
            << std::hex << std::setfill('0') << std::setw(16) 
            << flow_bulk_session_vid << ".jsonl.gz";

        return oss.str();
    }

    bool FlowDumpWriter::openFile(
            _In_ const std::string& file_path,
            _Out_ gzFile& gz_file)
    {
        SWSS_LOG_ENTER();

        // Create directory if it doesn't exist
        // Extract directory path from file path
        size_t last_slash = file_path.find_last_of('/');
        if (last_slash != std::string::npos)
        {
            std::string dir_path = file_path.substr(0, last_slash);
            struct stat st;
            if (stat(dir_path.c_str(), &st) != 0)
            {
                // Directory doesn't exist, create it recursively
                // Create parent directories first
                size_t pos = 0;
                while ((pos = dir_path.find('/', pos + 1)) != std::string::npos)
                {
                    std::string parent_dir = dir_path.substr(0, pos);
                    if (stat(parent_dir.c_str(), &st) != 0)
                    {
                        if (mkdir(parent_dir.c_str(), 0755) != 0 && errno != EEXIST)
                        {
                            SWSS_LOG_ERROR("Failed to create directory %s: %s", parent_dir.c_str(), strerror(errno));
                            return false;
                        }
                    }
                }
                // Create the final directory
                if (mkdir(dir_path.c_str(), 0755) != 0 && errno != EEXIST)
                {
                    SWSS_LOG_ERROR("Failed to create directory %s: %s", dir_path.c_str(), strerror(errno));
                    return false;
                }
            }
        }

        // Open file in append mode (a) with gzip compression
        gz_file = gzopen(file_path.c_str(), "ab");
        if (gz_file == nullptr)
        {
            SWSS_LOG_ERROR("Failed to open file %s for writing", file_path.c_str());
            return false;
        }

        SWSS_LOG_DEBUG("Opened flow dump file: %s", file_path.c_str());

        return true;
    }

    bool FlowDumpWriter::writeData(
            _In_ gzFile gz_file,
            _In_ const std::string& data)
    {
        SWSS_LOG_ENTER();

        if (gz_file == nullptr)
        {
            SWSS_LOG_ERROR("File not open");
            return false;
        }

        if (data.empty())
        {
            return true;
        }

        // gzwrite automatically compresses data when writing to a file opened with gzopen
        // Write all data in one go for better compression efficiency
        // gzwrite expects unsigned int for length
        unsigned int len = static_cast<unsigned int>(data.length());
        int written = gzwrite(gz_file, data.c_str(), len);

        if (written != static_cast<int>(len))
        {
            SWSS_LOG_ERROR("Failed to write data to file: wrote %d of %u bytes", written, len);
            return false;
        }

        return true;
    }

    void FlowDumpWriter::flush(
            _In_ gzFile gz_file)
    {
        SWSS_LOG_ENTER();

        if (gz_file != nullptr)
        {
            gzflush(gz_file, Z_SYNC_FLUSH);
        }
    }

    bool FlowDumpWriter::writeFlowDumpData(
            _In_ const FlowDumpDataPtr& data,
            _In_ sai_object_id_t flow_bulk_session_vid)
    {
        SWSS_LOG_ENTER();

        if (data == nullptr)
        {
            SWSS_LOG_ERROR("FlowDumpData is null");
            return false;
        }

        // Generate file path from VID
        std::string file_path = getFilePath(flow_bulk_session_vid);

        // Open file at the beginning
        gzFile gz_file = nullptr;
        if (!openFile(file_path, gz_file))
        {
            return false;
        }

        // Convert all JSON lines to a single string with newlines
        std::ostringstream oss;
        for (const auto& json_line : data->json_lines)
        {
            oss << json_line.dump() << "\n";
        }
        std::string complete_data = oss.str();

        // Write all data in one go (gzwrite automatically compresses)
        bool success = writeData(gz_file, complete_data);
        if (!success)
        {
            SWSS_LOG_ERROR("Failed to write flow dump data");
        }

        // Flush to ensure data is written and compressed
        flush(gz_file);

        // Close file after writing
        closeFile(gz_file, file_path);

        if (success)
        {
            SWSS_LOG_DEBUG("Wrote %zu JSON lines to file %s", data->json_lines.size(), file_path.c_str());
        }

        return success;
    }

    void FlowDumpWriter::closeFile(
            _In_ gzFile gz_file,
            _In_ const std::string& file_path)
    {
        SWSS_LOG_ENTER();

        if (gz_file != nullptr)
        {
            gzclose(gz_file);
            SWSS_LOG_DEBUG("Closed flow dump file: %s", file_path.c_str());
        }
    }

    const std::string& FlowDumpWriter::getBasePath() const
    {
        SWSS_LOG_ENTER();

        return m_base_path;
    }

    void FlowDumpWriter::setBasePath(
            _In_ const std::string& base_path)
    {
        SWSS_LOG_ENTER();

        m_base_path = base_path;
        SWSS_LOG_DEBUG("Set flow dump base path to: %s", m_base_path.c_str());
    }
}

