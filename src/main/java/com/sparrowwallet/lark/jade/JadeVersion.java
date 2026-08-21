package com.sparrowwallet.lark.jade;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
@JsonIgnoreProperties(ignoreUnknown = true)
public record JadeVersion(String JADE_VERSION, int JADE_OTA_MAX_CHUNK, String JADE_CONFIG, String BOARD_TYPE, String JADE_FEATURES,
                          String IDF_VERSION, String CHIP_FEATURES, String EFUSEMAC, int BATTERY_STATUS, JadeState JADE_STATE, JadeNetwork JADE_NETWORKS, boolean JADE_HAS_PIN) {
}
