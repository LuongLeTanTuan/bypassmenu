TARGET := iphone:clang:latest:14.0
ARCHS := arm64 arm64e

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = QoSMetrics
QoSMetrics_FILES = Tweak.x
QoSMetrics_CFLAGS = -fobjc-arc -Wno-deprecated-declarations
QoSMetrics_FRAMEWORKS = Foundation UIKit
QoSMetrics_LIBRARIES = substrate

include $(THEOS_MAKE_PATH)/tweak.mk
