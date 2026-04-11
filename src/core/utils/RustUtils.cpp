/**
 * Copyright (C) 2021-2024 Saturneric <eric@bktus.com>
 *
 * This file is part of GpgFrontend.
 *
 * GpgFrontend is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * GpgFrontend is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GpgFrontend. If not, see <https://www.gnu.org/licenses/>.
 *
 * The initial version of the source code is inherited from
 * the gpg4usb project, which is under GPL-3.0-or-later.
 *
 * All the source code of GpgFrontend was modified and released by
 * Saturneric <eric@bktus.com> starting on May 12, 2021.
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 */

#include "RustUtils.h"

namespace GpgFrontend {

auto KeyAlgoId2GfrKeyAlgo(const QString& algo_id) -> Rust::GfrKeyAlgo {
  LOG_D() << "key algo id: " << algo_id;

  if (algo_id == "ed25519") return Rust::GfrKeyAlgo::ED25519;
  if (algo_id == "cv25519") return Rust::GfrKeyAlgo::CV25519;
  if (algo_id == "nistp256") return Rust::GfrKeyAlgo::NISTP256;
  if (algo_id == "nistp384") return Rust::GfrKeyAlgo::NISTP384;
  if (algo_id == "nistp521") return Rust::GfrKeyAlgo::NISTP521;
  if (algo_id == "rsa2048") return Rust::GfrKeyAlgo::RSA2048;
  if (algo_id == "rsa3072") return Rust::GfrKeyAlgo::RSA3072;
  if (algo_id == "rsa4096") return Rust::GfrKeyAlgo::RSA4096;

  return Rust::GfrKeyAlgo::RSA2048;
}

auto GF_CORE_EXPORT GfrKeyAlgo2KeyAlgoName(Rust::GfrKeyAlgo algo) -> QString {
  switch (algo) {
    case Rust::GfrKeyAlgo::ED25519:
      return "ED25519";
    case Rust::GfrKeyAlgo::CV25519:
      return "CV25519";
    case Rust::GfrKeyAlgo::NISTP256:
      return "NIST P-256";
    case Rust::GfrKeyAlgo::NISTP384:
      return "NIST P-384";
    case Rust::GfrKeyAlgo::NISTP521:
      return "NIST P-521";
    case Rust::GfrKeyAlgo::RSA2048:
      return "RSA 2048";
    case Rust::GfrKeyAlgo::RSA3072:
      return "RSA 3072";
    case Rust::GfrKeyAlgo::RSA4096:
      return "RSA 4096";
    default:
      return "Unknown";
  }
}

}  // namespace GpgFrontend
