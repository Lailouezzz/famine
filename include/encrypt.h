/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   encrypt.h                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: Antoine Massias <massias.antoine.pro@gm    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/12/20 12:17:52 by Antoine Mas       #+#    #+#             */
/*   Updated: 2025/12/20 12:18:40 by Antoine Mas      ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef ENCRYPT_H
# define ENCRYPT_H

# include <stdint.h>
# include <sys/types.h>

extern
void	xtea_encrypt(
			void *data,
			size_t size,
			const uint32_t key[4]
			);

extern
void	xtea_decrypt(
			void *data,
			size_t size,
			const uint32_t key[4]
			);

#endif
