AC_DEFUN([CREATE_HEX_VERSION],[

  # Emit a byte-packed hex version (0xMMmmpp00) so the major/minor extraction
  # in internal.h (>> 24, (>> 16) & 0xff) yields the correct components. The
  # previous decimal field widths (%0.2d%0.3d%0.3d) misaligned the bytes, e.g.
  # 2.1.0 produced 0x02001000 which reads back as v2.0.
  HEX_VERSION=`echo $VERSION | sed 's|[\-a-z0-9]*$||' | \
    awk -F. '{printf "0x%02x%02x%02x00", $[]1, $[]2, $[]3}'`
  AC_SUBST([HEX_VERSION])
])
