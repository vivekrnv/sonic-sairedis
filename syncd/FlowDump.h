#pragma once

#include <nlohmann/json.hpp>
#include <vector>
#include <memory>
#include <string>
#include <zlib.h>

extern "C" {
#include "sai.h"
#include "saimetadata.h"
}

namespace syncd
{
    /**
     * @brief Structure to hold flow dump data as JSON lines
     *
     * This structure is used to pass flow entry data from NotificationHandler
     * (vendor SAI context) to NotificationProcessor (syncd context) via NotificationQueue.
     * Using shared_ptr avoids copying heavy JSON data structures.
     */
    struct FlowDumpData
    {
        /**
         * @brief Vector of JSON objects, each representing a flow entry
         *
         * Each JSON object contains the flow_entry fields and attributes
         * serialized according to the flow dump format specification.
         */
        std::vector<nlohmann::json> json_lines;
    };

    using FlowDumpDataPtr = std::shared_ptr<FlowDumpData>;

    /**
     * @brief Singleton class for serializing flow dump data to JSON lines
     *
     * This class handles the conversion of SAI flow_entry and attributes
     * to JSON format according to the flow dump specification.
     * Maintains separation of concerns by isolating serialization logic.
     */
    class FlowDumpSerializer
    {
        public:

            /**
             * @brief Get the singleton instance
             */
            static FlowDumpSerializer& getInstance();

            /**
             * @brief Serialize flow bulk get session event data to JSON lines
             *
             * Converts flow_entry and attributes from SAI notification data
             * into JSON lines format for file dumping.
             *
             * @param flow_bulk_session_id Session ID (RID format)
             * @param count Number of event data items
             * @param data Array of flow bulk get session event data
             * @return FlowDumpDataPtr containing JSON lines, or nullptr if no FLOW_ENTRY events
             */
            FlowDumpDataPtr serializeToJsonLines(
                    _In_ sai_object_id_t flow_bulk_session_id,
                    _In_ uint32_t count,
                    _In_ const sai_flow_bulk_get_session_event_data_t *data);

        private:

            FlowDumpSerializer() = default;
            ~FlowDumpSerializer() = default;

            // Delete copy constructor and assignment operator
            FlowDumpSerializer(const FlowDumpSerializer&) = delete;
            FlowDumpSerializer& operator=(const FlowDumpSerializer&) = delete;

            /**
             * @brief Convert a single flow_entry and its attributes to JSON
             *
             * @param event_data Flow bulk get session event data containing flow_entry and attributes
             * @return JSON object representing the flow entry
             */
            nlohmann::json serializeFlowEntryToJson(
                    _In_ const sai_flow_bulk_get_session_event_data_t& event_data);

            /**
             * @brief Serialize a single attribute to JSON value
             *
             * @param attr Attribute to serialize
             * @param meta Attribute metadata
             * @return JSON value (can be number, string, bool, etc.)
             */
            nlohmann::json serializeAttributeValue(
                    _In_ const sai_attribute_t& attr,
                    _In_ const sai_attr_metadata_t* meta);
    };

    /**
     * @brief Singleton class responsible for writing flow dump data to compressed files
     *
     * This class handles:
     * - Opening/closing gzip-compressed files
     * - Writing JSON lines to files
     * - Compressing data before writing
     * - File path generation based on flow bulk session ID (VID)
     *
     * Separation of concerns: This class only handles file I/O and compression.
     * It does not handle notification processing or data serialization.
     */
    class FlowDumpWriter
    {
        public:

            /**
             * @brief Default base path for flow dump files
             */
            static constexpr const char* DEFAULT_BASE_PATH = "/var/dump/flows/";

            /**
             * @brief Get the singleton instance
             */
            static FlowDumpWriter& getInstance();

            /**
             * @brief Write flow dump data to file
             *
             * Generates file path from VID, opens the file, writes JSON lines,
             * compresses, and closes the file.
             * File format: <base_path>/flow_dump_<VID>.jsonl.gz
             *
             * @param data Flow dump data containing JSON lines
             * @param flow_bulk_session_vid Session ID in VID format (0xXXXXX)
             * @return true on success, false on failure
             */
            bool writeFlowDumpData(
                    _In_ const FlowDumpDataPtr& data,
                    _In_ sai_object_id_t flow_bulk_session_vid);

            /**
             * @brief Get the base path for flow dump files
             *
             * @return Current base path string
             */
            const std::string& getBasePath() const;

            /**
             * @brief Set the base path for flow dump files
             *
             * @param base_path New base path (should end with '/')
             */
            void setBasePath(
                    _In_ const std::string& base_path);

        private:

            FlowDumpWriter();
            ~FlowDumpWriter();

            // Delete copy constructor and assignment operator
            FlowDumpWriter(const FlowDumpWriter&) = delete;
            FlowDumpWriter& operator=(const FlowDumpWriter&) = delete;

            /**
             * @brief Get file path for a given flow bulk session ID (VID)
             *
             * @param flow_bulk_session_vid VID format (0xXXXXX)
             * @return File path string
             */
            std::string getFilePath(
                    _In_ sai_object_id_t flow_bulk_session_vid) const;

            /**
             * @brief Open file for writing (creates if doesn't exist, appends if exists)
             *
             * @param file_path Path to the file
             * @param gz_file Output parameter for the opened file handle
             * @return true on success, false on failure
             */
            bool openFile(
                    _In_ const std::string& file_path,
                    _Out_ gzFile& gz_file);

            /**
             * @brief Write complete data string to the compressed file
             *
             * @param gz_file File handle to write to
             * @param data Complete string containing all JSON lines with newlines
             * @return true on success, false on failure
             */
            bool writeData(
                    _In_ gzFile gz_file,
                    _In_ const std::string& data);

            /**
             * @brief Flush compressed data to file
             *
             * @param gz_file File handle to flush
             */
            void flush(
                    _In_ gzFile gz_file);

            /**
             * @brief Close the file handle
             *
             * @param gz_file File handle to close
             * @param file_path Path of the file being closed (for logging)
             */
            void closeFile(
                    _In_ gzFile gz_file,
                    _In_ const std::string& file_path);

        private:

            std::string m_base_path;
    };
}

