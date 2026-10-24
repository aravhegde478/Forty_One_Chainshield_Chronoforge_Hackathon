// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Stores report hashes with a timestamp. Only the hash is stored, never the report.
contract ReportRegistry {
    struct Anchor {
        address anchoredBy;
        uint64 timestamp;
    }

    mapping(bytes32 => Anchor) private anchors;

    event ReportAnchored(bytes32 indexed reportHash, address indexed anchoredBy, uint64 timestamp);

    function anchor(bytes32 reportHash) external {
        require(anchors[reportHash].timestamp == 0, "Already anchored");
        anchors[reportHash] = Anchor(msg.sender, uint64(block.timestamp));
        emit ReportAnchored(reportHash, msg.sender, uint64(block.timestamp));
    }

    function getAnchor(bytes32 reportHash) external view returns (address anchoredBy, uint64 timestamp) {
        Anchor memory a = anchors[reportHash];
        return (a.anchoredBy, a.timestamp);
    }

    function isAnchored(bytes32 reportHash) external view returns (bool) {
        return anchors[reportHash].timestamp != 0;
    }
}