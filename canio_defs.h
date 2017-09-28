#pragma once
#include <stdint.h>

#define CANIO_NODE_ALL ((uint32_t) 0xFF)
#define CANIO_STREAM_ALL ((uint32_t) 0xF)

/* Make ID */
#define CANIO_ID(node, stream) ((uint32_t) (((node) & CANIO_NODE_ALL) | ((stream) & CANIO_STREAM_ALL) << 8))
/* Deconstruct ID */
#define CANIO_NODE(id) ((id) & 0xFFU)
#define CANIO_STREAM(id) ((id) >> 8 & 0xFU)

/* Masks */
#define CANIO_NODE_MASK CANIO_ID(CANIO_NODE_ALL, 0)
#define CANIO_STREAM_MASK CANIO_ID(0, CANIO_STREAM_ALL)
#define CANIO_NODE_STREAM_MASK CANIO_ID(CANIO_NODE_ALL, CANIO_STREAM_ALL)

/* Node/stream CAN ID generators */
#define CANIO_STDOUT(node) CANIO_ID(node, 1)
#define CANIO_STDIN(node) CANIO_ID(node, 0)
#define CANIO_ALL(node) CANIO_ID(node, CANIO_STREAM_ALL)
