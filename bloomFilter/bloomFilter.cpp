#include <iostream>
#include <vector>
#include <string>
#include <thread>
#include <chrono>
#include <functional>
#include <fstream>
#include <unordered_map>
#include <ctime>
#include <iomanip>
#include <sstream>
#include "xxhash.h" // Include xxHash header

class UltraFastBloomFilter {
public:
    UltraFastBloomFilter(size_t size, size_t numHashFunctions)
        : bitArray(size), numHashFunctions(numHashFunctions) {}

    void add(const std::string& item) {
        for (size_t i = 0; i < numHashFunctions; ++i) {
            size_t hashValue = hash(item, i) % bitArray.size();
            bitArray[hashValue] = true;
        }
    }

    bool contains(const std::string& item) const {
        for (size_t i = 0; i < numHashFunctions; ++i) {
            size_t hashValue = hash(item, i) % bitArray.size();
            if (!bitArray[hashValue]) {
                return false; // Definitely not in the set
            }
        }
        return true; // Possibly in the set
    }

private:
    std::vector<bool> bitArray;
    size_t numHashFunctions;

    size_t hash(const std::string& item, size_t seed) const {
        return XXH64(item.c_str(), item.size(), seed); // Use xxHash for hashing
    }
};

class NetworkMonitor {
public:
    void logSuspiciousIP(const std::string& ip) {
        std::ofstream logFile("suspicious_ips.log", std::ios_base::app);
        if (logFile.is_open()) {
            logFile << "Suspicious IP detected: " << ip << " at " << currentTime() << "\n";
        }
    }

    void monitorNetworkTraffic(UltraFastBloomFilter& bloomFilter) {
        // Simulated network packets
        std::vector<std::string> networkPackets = {
            "192.168.1.1", "10.0.0.5", "172.16.0.10",
            "192.168.1.100", "10.0.0.6", "203.0.113.45",
            "203.0.113.45", "203.0.113.45", // Repeated IP
            "203.0.113.45", "203.0.113.45", // Exceeding threshold
            "203.0.113.45", // Another repeated IP to definitely exceed threshold
            "203.0.113.45",  // And one more to ensure we exceed the threshold
            /*"192.168.1.5"*/   // Potential False Positives
        };

        for (const auto& ip : networkPackets) {
            auto now = std::time(nullptr);
            connectionCounts[ip]++;
            timestamps[ip].push_back(now);

            if (bloomFilter.contains(ip)) {
                std::cout << "ALERT: " << ip << " has been seen before!\n";
                logSuspiciousIP(ip);
            }
            else {
                std::cout << "New IP detected: " << ip << "\n";
                bloomFilter.add(ip); // Add new IP to the filter
            }

            // Check for potential threat based on connection frequency
            checkForThreat(ip, now);

            // Simulate time delay for incoming packets
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }

private:
    std::unordered_map<std::string, int> connectionCounts; // Count connections for each IP
    std::unordered_map<std::string, std::vector<std::time_t>> timestamps; // Track connection timestamps
    const int connectionThreshold = 5; // Threshold for alerts
    const int timeWindow = 10; // Time window in seconds

    void checkForThreat(const std::string& ip, std::time_t now) {
        // Remove old timestamps
        if (timestamps[ip].size() > 0) {
            while (!timestamps[ip].empty() && (now - timestamps[ip].front() > timeWindow)) {
                timestamps[ip].erase(timestamps[ip].begin());
            }
        }

        if (timestamps[ip].size() > connectionThreshold) {
            std::cout << "ALERT: " << ip << " is exceeding connection threshold!\n";
            logSuspiciousIP(ip);
        }
    }

    //std::string currentTime() const {
    //    std::time_t now = std::time(nullptr);
    //    std::tm localTime;
    //    localtime_s(&localTime, &now); // Thread-safe local time conversion
    //    std::ostringstream oss;
    //    oss << std::put_time(&localTime, "%Y-%m-%d %H:%M:%S"); // Format time
    //    return oss.str();
    //}
    std::string currentTime() const {
        auto now = std::chrono::system_clock::now();
        auto in_time_t = std::chrono::system_clock::to_time_t(now);
        auto milliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;

        std::tm localTime;
        localtime_s(&localTime, &in_time_t); // Thread-safe local time conversion

        std::ostringstream oss;
        oss << std::put_time(&localTime, "%Y-%m-%d %H:%M:%S"); // Format time
        oss << "." << std::setw(3) << std::setfill('0') << milliseconds.count(); // Add milliseconds

        return oss.str();
    }
};

int main() {
    const size_t filterSize = 1000; // Size of the bit array
    const size_t numHashFuncs = 3;  // Number of hash functions

    UltraFastBloomFilter bloomFilter(filterSize, numHashFuncs);
    NetworkMonitor monitor;

    monitor.monitorNetworkTraffic(bloomFilter);

    return 0;
}

//#include <iostream>
//#include <vector>
//#include <string>
//#include <thread>
//#include <chrono>
//#include <functional>
//#include <fstream>
//#include <unordered_map>
//#include <ctime>
//#include <iomanip>
//#include <sstream>
//
//class UltraFastBloomFilter {
//public:
//    UltraFastBloomFilter(size_t size, size_t numHashFunctions)
//        : bitArray(size), numHashFunctions(numHashFunctions) {}
//
//    void add(const std::string& item) {
//        for (size_t i = 0; i < numHashFunctions; ++i) {
//            size_t hashValue = hash(item, i) % bitArray.size();
//            bitArray[hashValue] = true;
//        }
//    }
//
//    bool contains(const std::string& item) const {
//        for (size_t i = 0; i < numHashFunctions; ++i) {
//            size_t hashValue = hash(item, i) % bitArray.size();
//            if (!bitArray[hashValue]) {
//                return false; // Definitely not in the set
//            }
//        }
//        return true; // Possibly in the set
//    }
//
//private:
//    std::vector<bool> bitArray;
//    size_t numHashFunctions;
//
//    size_t hash(const std::string& item, size_t seed) const {
//        std::hash<std::string> hasher;
//        return hasher(item) ^ (seed * 0x5bd1e995);
//    }
//};
//
//class NetworkMonitor {
//public:
//    void logSuspiciousIP(const std::string& ip) {
//        std::ofstream logFile("suspicious_ips.log", std::ios_base::app);
//        if (logFile.is_open()) {
//            logFile << "Suspicious IP detected: " << ip << " at " << currentTime() << "\n";
//        }
//    }
//
//    void monitorNetworkTraffic(UltraFastBloomFilter& bloomFilter) {
//        // Simulated network packets
//        std::vector<std::string> networkPackets = {
//            "192.168.1.1", "10.0.0.5", "172.16.0.10",
//            "192.168.1.100", "10.0.0.6", "203.0.113.45",
//            "203.0.113.45", "203.0.113.45", // Repeated IP
//            "203.0.113.45", "203.0.113.45", // Exceeding threshold
//            "203.0.113.45", // Another repeated IP to definitely exceed threshold
//            "203.0.113.45"  // And one more to ensure we exceed the threshold
//        };
//
//        for (const auto& ip : networkPackets) {
//            auto now = std::time(nullptr);
//            connectionCounts[ip]++;
//            timestamps[ip].push_back(now);
//
//            if (bloomFilter.contains(ip)) {
//                std::cout << "ALERT: " << ip << " has been seen before!\n";
//                logSuspiciousIP(ip);
//            }
//            else {
//                std::cout << "New IP detected: " << ip << "\n";
//                bloomFilter.add(ip); // Add new IP to the filter
//            }
//
//            // Check for potential threat based on connection frequency
//            checkForThreat(ip, now);
//
//            // Simulate time delay for incoming packets
//            std::this_thread::sleep_for(std::chrono::milliseconds(100));
//        }
//    }
//
//private:
//    std::unordered_map<std::string, int> connectionCounts; // Count connections for each IP
//    std::unordered_map<std::string, std::vector<std::time_t>> timestamps; // Track connection timestamps
//    const int connectionThreshold = 5; // Threshold for alerts
//    const int timeWindow = 10; // Time window in seconds
//
//    void checkForThreat(const std::string& ip, std::time_t now) {
//        // Remove old timestamps
//        if (timestamps[ip].size() > 0) {
//            while (!timestamps[ip].empty() && (now - timestamps[ip].front() > timeWindow)) {
//                timestamps[ip].erase(timestamps[ip].begin());
//            }
//        }
//
//        if (timestamps[ip].size() > connectionThreshold) {
//            std::cout << "ALERT: " << ip << " is exceeding connection threshold!\n";
//            logSuspiciousIP(ip);
//        }
//    }
//
//    std::string currentTime() const {
//        std::time_t now = std::time(nullptr);
//        std::tm localTime;
//        localtime_s(&localTime, &now); // Thread-safe local time conversion
//        std::ostringstream oss;
//        oss << std::put_time(&localTime, "%Y-%m-%d %H:%M:%S"); // Format time
//        return oss.str();
//    }
//};
//
//int main() {
//    const size_t filterSize = 1000; // Size of the bit array
//    const size_t numHashFuncs = 3;  // Number of hash functions
//
//    UltraFastBloomFilter bloomFilter(filterSize, numHashFuncs);
//    NetworkMonitor monitor;
//
//    monitor.monitorNetworkTraffic(bloomFilter);
//
//    return 0;
//}

//#include <iostream>
//#include <vector>
//#include <string>
//#include <thread>
//#include <chrono>
//#include <functional>
//
//class UltraFastBloomFilter {
//public:
//    UltraFastBloomFilter(size_t size, size_t numHashFunctions)
//        : bitArray(size), numHashFunctions(numHashFunctions) {}
//
//    void add(const std::string& item) {
//        for (size_t i = 0; i < numHashFunctions; ++i) {
//            size_t hashValue = hash(item, i) % bitArray.size();
//            bitArray[hashValue] = true;
//        }
//    }
//
//    bool contains(const std::string& item) const {
//        for (size_t i = 0; i < numHashFunctions; ++i) {
//            size_t hashValue = hash(item, i) % bitArray.size();
//            if (!bitArray[hashValue]) {
//                return false; // Definitely not in the set
//            }
//        }
//        return true; // Possibly in the set
//    }
//
//private:
//    std::vector<bool> bitArray;
//    size_t numHashFunctions;
//
//    size_t hash(const std::string& item, size_t seed) const {
//        std::hash<std::string> hasher;
//        return hasher(item) ^ (seed * 0x5bd1e995);
//    }
//};
//
//void monitorNetworkTraffic(UltraFastBloomFilter& bloomFilter) {
//    // Simulated network packets
//    std::vector<std::string> networkPackets = {
//        "192.168.1.1", "10.0.0.5", "172.16.0.10",
//        "192.168.1.100", "192.168.1.1", "10.0.0.6", "203.0.113.45" // New IP
//    };
//
//    for (const auto& ip : networkPackets) {
//        if (bloomFilter.contains(ip)) {
//            std::cout << "ALERT: " << ip << " has been seen before!\n";
//        }
//        else {
//            std::cout << "New IP detected: " << ip << "\n";
//            bloomFilter.add(ip); // Add new IP to the filter
//        }
//        // Simulate time delay for incoming packets
//        std::this_thread::sleep_for(std::chrono::milliseconds(100));
//    }
//}

//int main() {
//    const size_t filterSize = 1000; // Size of the bit array
//    const size_t numHashFuncs = 3;  // Number of hash functions
//
//    UltraFastBloomFilter bloomFilter(filterSize, numHashFuncs);
//
//    monitorNetworkTraffic(bloomFilter);
//
//    return 0;
//}

//#include <iostream>
//#include <vector>
//#include <string>
//
//class CountingBloomFilter {
//public:
//    CountingBloomFilter(size_t size, size_t hashCount)
//        : countArray(size, 0), hashCount(hashCount) {}
//
//    // Add an element to the Counting Bloom filter
//    void add(const std::string& element) {
//        for (size_t i = 0; i < hashCount; ++i) {
//            size_t hashValue = hash(element, i);
//            countArray[hashValue]++;
//        }
//    }
//
//    // Remove an element from the Counting Bloom filter
//    void remove(const std::string& element) {
//        for (size_t i = 0; i < hashCount; ++i) {
//            size_t hashValue = hash(element, i);
//            if (countArray[hashValue] > 0) {
//                countArray[hashValue]--;
//            }
//        }
//    }
//
//    // Check if an element is possibly in the Counting Bloom filter
//    bool contains(const std::string& element) const {
//        for (size_t i = 0; i < hashCount; ++i) {
//            size_t hashValue = hash(element, i);
//            if (countArray[hashValue] == 0) {
//                return false; // Definitely not in the set
//            }
//        }
//        return true; // Possibly in the set (could be a false positive)
//    }
//
//private:
//    std::vector<int> countArray; // The count array
//    size_t hashCount; // Number of hash functions
//
//    // Simple hash function using basic arithmetic
//    size_t hash(const std::string& element, size_t seed) const {
//        size_t hashValue = 0;
//        for (char c : element) {
//            hashValue = hashValue * 31 + c; // Simple polynomial hash
//        }
//        return (hashValue + seed) % countArray.size();
//    }
//};
//
//int main() {
//    // Create a Counting Bloom filter for detecting malicious IPs
//    const size_t filterSize = 1000; // Size of the count array
//    const size_t numHashes = 5;      // Number of hash functions
//    CountingBloomFilter bloomFilter(filterSize, numHashes);
//
//    // Example of adding malicious IPs
//    bloomFilter.add("192.168.1.1");
//    bloomFilter.add("10.0.0.5");
//    bloomFilter.add("172.16.0.10");
//
//    // Check for malicious IPs
//    std::string testIP;
//    std::cout << "Enter an IP address to check: ";
//    std::cin >> testIP;
//
//    if (bloomFilter.contains(testIP)) {
//        std::cout << "Warning: This IP may be malicious (false positive possible)." << std::endl;
//    }
//    else {
//        std::cout << "This IP is not malicious." << std::endl;
//    }
//
//    // Remove an IP
//    std::string removeIP = "192.168.1.1";
//    bloomFilter.remove(removeIP);
//    std::cout << "Removed IP: " << removeIP << std::endl;
//
//    return 0;
//}


//// Standard Bloom Filter Implementation
//#include <iostream>
//#include <vector>
//#include <string>
//#include <bitset>
//#include <cmath>
//
//class BloomFilter {
//public:
//    BloomFilter(size_t size, size_t hashCount)
//        : bitArray(size), hashCount(hashCount) {}
//
//    // Add an element to the Bloom filter
//    void add(const std::string& element) {
//        for (size_t i = 0; i < hashCount; ++i) {
//            size_t hashValue = hash(element, i);
//            bitArray.set(hashValue); // Set the bit at hashValue to true
//        }
//    }
//
//    // Check if an element is possibly in the Bloom filter
//    bool contains(const std::string& element) const {
//        for (size_t i = 0; i < hashCount; ++i) {
//            size_t hashValue = hash(element, i);
//            if (!bitArray.test(hashValue)) {
//                return false; // Definitely not in the set
//            }
//        }
//        return true; // Possibly in the set (could be a false positive)
//    }
//
//private:
//    std::bitset<1000> bitArray; // The bit array (fixed size for simplicity)
//    size_t hashCount; // Number of hash functions
//
//    // Simple hash function using basic arithmetic
//    size_t hash(const std::string& element, size_t seed) const {
//        size_t hashValue = 0;
//        for (char c : element) {
//            hashValue = hashValue * 31 + c; // Simple polynomial hash
//        }
//        return (hashValue + seed) % bitArray.size();
//    }
//};
//
//int main() {
//    // Create a Bloom filter for detecting malicious IPs
//    const size_t numHashes = 5; // Number of hash functions
//    BloomFilter bloomFilter(1000, numHashes); // Size defined in bitset
//
//    // Example of adding malicious IPs
//    bloomFilter.add("192.168.1.1");
//    bloomFilter.add("10.0.0.5");
//    bloomFilter.add("172.16.0.10");
//
//    // Check for malicious IPs
//    std::string testIP;
//    std::cout << "Enter an IP address to check: ";
//    std::cin >> testIP;
//
//    if (bloomFilter.contains(testIP)) {
//        std::cout << "Warning: This IP may be malicious (false positive possible)." << std::endl;
//    }
//    else {
//        std::cout << "This IP is not malicious." << std::endl;
//    }
//
//    return 0;
//}


//#include <iostream>
//#include <cstdint>
////#include <cstring>
//#include <string>
//
//const int BLOOM_SIZE = 1000; // Size for the Bloom Filter
//const int HASH_FUNCTIONS = 3; // Number of hash functions
//
//class BloomFilter {
//public:
//    BloomFilter() {
//        memset(bits, 0, sizeof(bits)); // Initialize bits to 0
//    }
//
//    void add(uint32_t ip) {
//        for (int i = 0; i < HASH_FUNCTIONS; ++i) {
//            size_t hash = hashFunction(ip, i) % BLOOM_SIZE;
//            bits[hash] = 1; // Set the bit to 1
//        }
//    }
//
//    bool contains(uint32_t ip) const {
//        for (int i = 0; i < HASH_FUNCTIONS; ++i) {
//            size_t hash = hashFunction(ip, i) % BLOOM_SIZE;
//            if (bits[hash] == 0) {
//                return false; // If any bit is 0, item is not present
//            }
//        }
//        return true; // All bits are set
//    }
//
//private:
//    char bits[BLOOM_SIZE]; // Bit array for the Bloom Filter
//
//    size_t hashFunction(uint32_t ip, int seed) const {
//        return (ip ^ seed) % BLOOM_SIZE; // Simple hash function
//    }
//};
//
//// Radix Tree Node
//struct RadixTreeNode {
//    uint32_t prefix; // Store prefix as uint32_t
//    int mask; // Store subnet mask
//    RadixTreeNode* children[256]; // Children for each character
//
//    RadixTreeNode() : prefix(0), mask(0) {
//        memset(children, 0, sizeof(children));
//    }
//};
//
//class RadixTree {
//public:
//    RadixTree() : root(new RadixTreeNode()) {}
//
//    void insert(uint32_t prefix, int mask) {
//        insertNode(root, prefix, mask);
//    }
//
//    uint32_t longestPrefixMatch(uint32_t ip) {
//        return longestPrefixMatchNode(root, ip, 0);
//    }
//
//private:
//    RadixTreeNode* root;
//
//    void insertNode(RadixTreeNode* node, uint32_t prefix, int mask) {
//        RadixTreeNode* current = node;
//        for (int i = 31; i >= 32 - mask; --i) {
//            int bit = (prefix >> i) & 1;
//            if (current->children[bit] == nullptr) {
//                current->children[bit] = new RadixTreeNode();
//            }
//            current = current->children[bit];
//        }
//        current->prefix = prefix; // Store prefix
//        current->mask = mask; // Store mask
//    }
//
//    uint32_t longestPrefixMatchNode(RadixTreeNode* node, uint32_t ip, int depth) {
//        uint32_t longestMatch = 0;
//        int maxMask = 0;
//
//        for (int i = 31; i >= 0; --i) {
//            int bit = (ip >> i) & 1;
//            if (node->children[bit] != nullptr) {
//                node = node->children[bit];
//                if (node->mask > maxMask) {
//                    longestMatch = node->prefix; // Update longest match
//                    maxMask = node->mask;
//                }
//            }
//            else {
//                break; // No further matches
//            }
//        }
//
//        return longestMatch; // Return the longest prefix found
//    }
//};
//
//class NIDS {
//public:
//    NIDS() {}
//
//    void addMaliciousIP(uint32_t ip) {
//        bloomFilter.add(ip);
//    }
//
//    bool detectIP(uint32_t ip) {
//        return bloomFilter.contains(ip);
//    }
//
//    void addPrefixForMatching(uint32_t prefix, int mask) {
//        radixTree.insert(prefix, mask);
//    }
//
//    uint32_t matchIPPrefix(uint32_t ip) {
//        return radixTree.longestPrefixMatch(ip);
//    }
//
//private:
//    BloomFilter bloomFilter;
//    RadixTree radixTree;
//};
//
//// Helper function to convert IP string to uint32_t
//uint32_t ipToUint32(const std::string& ip) {
//    /*uint32_t result = 0;
//    int byte;
//    size_t start = 0, end;
//    for (int i = 0; i < 4; ++i) {
//        end = ip.find('.', start);
//        if (end == std::string::npos) end = ip.length();
//        byte = std::stoi(ip.substr(start, end - start));
//        result = (result << 8) | (byte & 0xFF);
//        start = end + 1;
//    }
//    return result;*/
//
//    int parts[4] = { 0 };
//    int num = 0, index = 0;
//    if (!(ip[0] >= '0' && ip[0] <= '9')) {
//        return -1;
//    }
//
//    for (char ch : ip) {
//        if (ch >= '0' && ch <= '9') {
//            num = num * 10 + (ch - '0');
//        }
//        else if (ch == '.') {
//            if (index >= 4 || num > 255)
//                return -1;  // More than 4 parts or segment > 255
//            parts[index++] = num;
//            num = 0;
//        }
//        else {
//            return -1;  // Invalid character
//        }
//    }
//
//    if (index >= 4 || num > 255) return -1;
//    // last num is not added within the loop 
//    // since we have null instead of "."
//    parts[index] = num;
//
//    return (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3];
//}
//
//std::string Uint32ToIp(unsigned int num) {
//    // Convert the integer to the dotted-decimal IP address format
//    return std::to_string((num >> 24) & 0xFF) + "." +
//        std::to_string((num >> 16) & 0xFF) + "." +
//        std::to_string((num >> 8) & 0xFF) + "." +
//        std::to_string(num & 0xFF);
//}
//
//// Example usage
//int main() {
//    NIDS nids;
//
//    // Add malicious IPs to Bloom Filter
//    nids.addMaliciousIP(ipToUint32("192.168.1.10"));
//    nids.addMaliciousIP(ipToUint32("10.0.0.5"));
//
//    // Check for detection
//    uint32_t ipToCheck = ipToUint32("192.168.1.10");
//    std::cout << "Is " << "192.168.1.10" << " a known malicious IP? "
//        << (nids.detectIP(ipToCheck) ? "Yes" : "No") << std::endl;
//
//    // Add prefixes for longest prefix matching
//    nids.addPrefixForMatching(ipToUint32("192.168.1.0"), 24);
//    nids.addPrefixForMatching(ipToUint32("10.0.0.0"), 8);
//
//    // Match IP with prefixes
//    uint32_t matchedPrefix = nids.matchIPPrefix(ipToUint32("192.168.1.15"));
//    /*std::cout << "Longest matching prefix for 192.168.1.15: "
//        << (matchedPrefix ? std::to_string((matchedPrefix >> 24) & 0xFF) + "." +
//            std::to_string((matchedPrefix >> 16) & 0xFF) + "." +
//            std::to_string((matchedPrefix >> 8) & 0xFF) + "." +
//            std::to_string(matchedPrefix & 0xFF) : "None")
//        << std::endl;*/
//
//    std::cout << "Longest matching prefix for 192.168.1.15: "
//        << (matchedPrefix ? Uint32ToIp(matchedPrefix) : "None")
//        << std::endl;
//
//    return 0;
//}

//#include <iostream>
//#include <vector>
//#include <string>
//#include <functional>
//
//class BloomFilter {
//private:
//    std::vector<bool> bitArray; // The bit array
//    size_t size;                // Size of the bit array
//    size_t numHashFunctions;    // Number of hash functions
//
//    // Hash functions
//    size_t hash1(const std::string& str) {
//        return std::hash<std::string>{}(str) % size;
//    }
//
//    size_t hash2(const std::string& str) {
//        return (std::hash<std::string>{}(str) * 31) % size;
//    }
//
//public:
//    // Constructor
//    BloomFilter(size_t size, size_t numHashFunctions)
//        : size(size), numHashFunctions(numHashFunctions) {
//        bitArray.resize(size);
//    }
//
//    // Add an element to the Bloom Filter
//    void add(const std::string& str) {
//        size_t index1 = hash1(str);
//        size_t index2 = hash2(str);
//        bitArray[index1] = true;
//        bitArray[index2] = true;
//
//        // If numHashFunctions is more than 2, you could extend this
//        for (size_t i = 2; i < numHashFunctions; ++i) {
//            size_t index = (index1 + i * index2) % size; // Linear combination for additional hashes
//            bitArray[index] = true;
//        }
//    }
//
//    // Check if an element is in the Bloom Filter
//    bool contains(const std::string& str) {
//        size_t index1 = hash1(str);
//        size_t index2 = hash2(str);
//        if (!bitArray[index1] || !bitArray[index2]) {
//            return false; // Definitely not in the set
//        }
//
//        // For additional hash functions
//        for (size_t i = 2; i < numHashFunctions; ++i) {
//            size_t index = (index1 + i * index2) % size;
//            if (!bitArray[index]) {
//                return false; // Definitely not in the set
//            }
//        }
//        return true; // Might be in the set
//    }
//};
//
//int main() {
//    BloomFilter bloomFilter(100, 3); // Size of 100 bits and 3 hash functions
//
//    bloomFilter.add("apple");
//    bloomFilter.add("banana");
//    bloomFilter.add("grape");
//
//    std::cout << "Contains 'apple': " << bloomFilter.contains("apple") << std::endl; // Expected: true
//    std::cout << "Contains 'banana': " << bloomFilter.contains("banana") << std::endl; // Expected: true
//    std::cout << "Contains 'grape': " << bloomFilter.contains("grape") << std::endl; // Expected: true
//    std::cout << "Contains 'orange': " << bloomFilter.contains("orange") << std::endl; // Expected: false (might be true due to false positives)
//
//    return 0;
//}