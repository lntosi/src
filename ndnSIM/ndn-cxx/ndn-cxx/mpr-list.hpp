#ifndef NDN_MPR_LIST_HPP
#define NDN_MPR_LIST_HPP

#include "ndn-cxx/delegation.hpp"

#include <initializer_list>

namespace ndn {

/** \brief represents a list of MPRs
 *
 *  MPRs are stored in an std::vector, under the assumption that there is usually only a
 *  small number of Delegations, so that copying is acceptable when they are modified.
 */
class MPRList
{
public:
  class Error : public tlv::Error
  {
  public:
    using tlv::Error::Error;
  };

  /** \brief construct an empty MPRList
   */
  MPRList();

  /** \brief construct a sorted MPRList with specified delegations
   *
   *  This is equivalent to inserting each delegation into an empty MPRList with INS_REPLACE
   *  conflict resolution.
   */
  MPRList(std::initializer_list<Delegation> dels);

  /** \brief decode a MPRList
   *  \sa wireDecode
   */
  explicit
  MPRList(const Block& block, bool wantSort = true);

  /** \brief encode into wire format
   *  \param encoder either an EncodingBuffer or an EncodingEstimator
   *  \param type TLV-TYPE number, either Content (for \p Link) or ForwardingHint
   *  \throw std::invalid_argument \p type is invalid
   *  \throw Error there is no Delegation
   */
  template<encoding::Tag TAG>
  size_t
  wireEncode(EncodingImpl<TAG>& encoder, uint32_t type = tlv::MPRList) const;

  /** \brief decode a MPRList
   *  \param block either a Content block (from \p Link) or a ForwardingHint block
   *  \param wantSort if true, delegations are sorted
   *  \throw Error the block cannot be parsed as a list of Delegations
   */
  void
  wireDecode(const Block& block, bool wantSort = true);

  bool
  isSorted() const noexcept
  {
    return m_isSorted;
  }

  using const_iterator = std::vector<Delegation>::const_iterator;

  const_iterator
  begin() const noexcept
  {
    return m_dels.begin();
  }

  const_iterator
  end() const noexcept
  {
    return m_dels.end();
  }

  NDN_CXX_NODISCARD bool
  empty() const noexcept
  {
    return m_dels.empty();
  }

  size_t
  size() const noexcept
  {
    return m_dels.size();
  }

  /** \brief get the i-th delegation
   *  \pre i < size()
   */
  const Delegation&
  operator[](size_t i) const
  {
    BOOST_ASSERT(i < size());
    return m_dels[i];
  }

  /** \brief get the i-th delegation
   *  \throw std::out_of_range i >= size()
   */
  const Delegation&
  at(size_t i) const
  {
    return m_dels.at(i);
  }

public: // modifiers
  /** \brief sort the delegation list
   *  \post isSorted() == true
   *  \post Delegations are sorted in increasing preference order.
   *
   *  A MPRList can be constructed as sorted or unsorted. In most cases, it is recommended
   *  to use a sorted MPRList. An unsorted MPRList is useful for extracting the i-th
   *  delegation from a received ForwardingHint or Link object.
   *
   *  This method turns an unsorted MPRList into a sorted MPRList.
   *  If access to unsorted MPRList is not needed, it is more efficient to sort the
   *  MPRList in wireDecode.
   */
  void
  sort();

  /** \brief what to do when inserting a duplicate name
   */
  enum InsertConflictResolution {
    /** \brief existing delegation(s) with the same name are replaced with the new delegation
     */
    INS_REPLACE,

    /** \brief multiple delegations with the same name are kept in the MPRList
     *  \note This is NOT RECOMMENDED by Link specification.
     */
    INS_APPEND,

    /** \brief new delegation is not inserted if an existing delegation has the same name
     */
    INS_SKIP
  };

  /** \brief insert Delegation
   *  \return whether inserted
   */
  bool
  insert(uint64_t preference, const Name& name,
         InsertConflictResolution onConflict = INS_REPLACE);

  /** \brief insert Delegation
   *  \return whether inserted
   */
  bool
  insert(const Delegation& del, InsertConflictResolution onConflict = INS_REPLACE)
  {
    return this->insert(del.preference, del.name, onConflict);
  }

  /** \brief delete Delegation(s) with specified preference and name
   *  \return count of erased Delegation(s)
   */
  size_t
  erase(uint64_t preference, const Name& name)
  {
    return this->eraseImpl(preference, name);
  }

  /** \brief delete Delegation(s) with matching preference and name
   *  \return count of erased Delegation(s)
   */
  size_t
  erase(const Delegation& del)
  {
    return this->eraseImpl(del.preference, del.name);
  }

  /** \brief erase Delegation(s) with specified name
   *  \return count of erased Delegation(s)
   */
  size_t
  erase(const Name& name)
  {
    return this->eraseImpl(nullopt, name);
  }

private:
  static bool
  isValidTlvType(uint32_t type);

  void
  insertImpl(uint64_t preference, const Name& name);

  size_t
  eraseImpl(optional<uint64_t> preference, const Name& name);

private: // non-member operators
  // NOTE: the following "hidden friend" operators are available via
  //       argument-dependent lookup only and must be defined inline.

  /** \brief Compare whether two DelegationLists are equal.
   *  \note Order matters! If two DelegationLists contain the same Delegations but at least one is
   *        unsorted, they may compare unequal if the Delegations appear in different order.
   */
  friend bool
  operator==(const MPRList& lhs, const MPRList& rhs)
  {
    return lhs.m_dels == rhs.m_dels;
  }

  friend bool
  operator!=(const MPRList& lhs, const MPRList& rhs)
  {
    return lhs.m_dels != rhs.m_dels;
  }

private:
  bool m_isSorted;

  /** \brief delegation container; its contents are sorted when \p m_isSorted is true
   *  \note This container is a member field rather than a base class, in order to ensure contents
   *        are sorted when \p m_isSorted is true.
   *  \note A vector is chosen instead of a std::set, so that the container can be unsorted when
   *        \p m_isSorted is false. This container is expected to have less than seven items, and
   *        therefore the overhead of moving items during insertion and deletion is small.
   */
  std::vector<Delegation> m_dels;
};

#ifndef DOXYGEN
extern template size_t
MPRList::wireEncode<encoding::EncoderTag>(EncodingBuffer&, uint32_t) const;

extern template size_t
MPRList::wireEncode<encoding::EstimatorTag>(EncodingEstimator&, uint32_t) const;
#endif

std::ostream&
operator<<(std::ostream& os, const MPRList& dl);

} // namespace ndn

#endif // NDN_MPR_LIST_HPP
