// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract CertificateStorage {
    struct Certificate {
        string hash;
        address issuer;
        uint256 timestamp;
    }

    mapping(string => Certificate) private certificates;

    event CertificateStored(string hash, address issuer, uint256 timestamp);

    function storeCertificate(string memory _hash) public {
        require(bytes(_hash).length > 0, "Hash cannot be empty");
        require(certificates[_hash].timestamp == 0, "Certificate already exists");

        certificates[_hash] = Certificate({
            hash: _hash,
            issuer: msg.sender,
            timestamp: block.timestamp
        });

        emit CertificateStored(_hash, msg.sender, block.timestamp);
    }

    function verifyCertificate(string memory _hash)
        public
        view
        returns (address issuer, uint256 timestamp)
    {
        Certificate memory cert = certificates[_hash];
        require(bytes(cert.hash).length > 0, "Certificate not found");
        return (cert.issuer, cert.timestamp);
    }
}