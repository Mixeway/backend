package io.mixeway.api.vulnmanage.model;

import lombok.Getter;
import lombok.Setter;

import java.util.List;

@Getter
@Setter
public class InfraScanMetadata {
    List<ScannedAddress> scannedAddresses;

}
